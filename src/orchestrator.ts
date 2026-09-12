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
import { strikeVerify, resolveFinding } from "./strike.js";

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
  if (mode === "ctf" || mode === "reverse-engineering" || mode === "offensive") {
    result = { target, allowed: true, enforcement: "off", reason: `mode=${mode} disables scope enforcement` };
  } else if (!scope.trim()) {
    result = { target, allowed: false, enforcement: "strict", reason: "no scope provided; refusing active testing" };
  } else {
    const inScope: string[] = [];
    const outScope: string[] = [];
    for (const raw of scope.split(/[,\n]/)) {
      const line = raw.trim();
      if (!line) continue;
      if (line.startsWith("-")) outScope.push(line.slice(1).trim());
      else inScope.push(line);
    }

    let host = target;
    host = host.replace(/^https?:\/\//, "");
    host = host.split("/")[0].split(":")[0];

    let decided = false;
    result = { target, allowed: false, enforcement: "strict", reason: `target '${host}' not in scope` };
    for (const exc of outScope) {
      if (exc && (host.includes(exc) || host.endsWith("." + exc.replace(/^\./, "")))) {
        result = { target, allowed: false, enforcement: "strict", reason: `target '${host}' is explicitly out of scope (${exc})` };
        decided = true;
        break;
      }
    }
    if (!decided) {
      for (const allowed of inScope) {
        const a = allowed.replace(/\*/g, "");
        if (!a) continue;
        if (host.includes(a) || host.endsWith("." + a.replace(/^\./, ""))) {
          result = { target, allowed: true, enforcement: "strict", reason: `matched in-scope pattern '${allowed}'` };
          decided = true;
          break;
        }
      }
    }
  }

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
export async function runLiveEngagement(url: string, scope = "", mode = "bug-bounty"): Promise<Record<string, unknown>> {
  const report: Record<string, unknown> = { banner: engagementBanner(url, mode), target: url, mode, findings: [], scope: null, status: "" };

  // Record the scope classification (intel for the report) — it does NOT gate.
  const sc = scopeCheck(url, scope, mode);
  report.scope = sc;

  const findings: Finding[] = [];
  for (const param of LIVE_SWEEP_PARAMS) {
    const verdict = await strikeVerify({ url, param });
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
  }

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
    "Autonomous live marker sweep. Each parameter was validated with a marker + " +
    "negative control; confirmed reflections are real findings, everything else " +
    "is a hypothesis or false positive. Re-run with explicit strike_verify for " +
    "deeper per-endpoint validation.";

  return report;
}
