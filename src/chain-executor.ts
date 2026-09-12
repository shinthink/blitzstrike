/** Generic chain executor — turn a finding's escalation chain into EXECUTED steps.
 *
 * chains.json steps are generic guidance (action + tool_hint + success_criteria),
 * not per-vuln code. This module interprets each step's tool_hint and runs the
 * matching deterministic operation, so the PIPELINE advances the finding through
 * its chain instead of leaving it as a hypothesis for the LLM:
 *
 *   tool_hint "strike_verify"  -> strike_verify (marker + negative control)
 *   tool_hint "crack_hash"     -> crack_hash on hashes in the finding's evidence
 *   tool_hint "scan_leaked_source" -> scan the finding's evidence text for sinks
 *   tool_hint "browser"        -> browser_validate (DOM/redirect/auth/csrf)
 *   tool_hint <catalog tool>   -> run_catalog_tool (sqlmap, nuclei, tplmap, ...)
 *   otherwise                  -> "deferred" with the exact action + tool for the LLM
 *
 * Target-agnostic: works for SQLi, SSRF, SSTI, LFI, JWT, deserialization, ... —
 * whatever chain the finding maps to, the deterministic parts get executed.
 */
import { strikeVerify, type StrikeVerdict } from "./strike.js";
import { crackHash } from "./hash.js";
import { scanSinks, detectSourceLeak, type SinkHit } from "./sinks.js";
import { toolForHint, runCatalogTool } from "./catalog.js";
import { browserValidate, type BrowserCheck } from "./browser.js";
import { driveChromeDevtools } from "./devtools.js";
import { driveBurpMCP } from "./burp-mcp.js";
import type { Finding } from "./finding.js";

export interface ChainStepDef {
  order: number;
  action: string;
  tool_hint?: string | null;
  success_criteria?: string | null;
  invariant_check?: string | null;
  negative_control?: string | null;
}

export interface ChainStepResult {
  order: number;
  action: string;
  tool_hint: string;
  executed: boolean;
  outcome: "executed" | "deferred" | "error";
  tool?: string;
  detail?: unknown;
}

// Blitz MCP finding-level tools — resolved by NAME (generic, no semantic bucket).
// A chain step whose tool_hint matches one of these names (or a documented alias)
// dispatches to the matching finding-level tool.
const BLITZ_FINDING_TOOLS: Record<string, (f: Finding) => Promise<Record<string, unknown>> | Record<string, unknown>> = {
  strike_verify: verifyFinding,
  crack_hash: crackFinding,
  hashcat: crackFinding, // chain alias -> crack
  hashid: crackFinding, // chain alias -> crack
  john: crackFinding, // chain alias -> crack
  scan_leaked_source: scanFinding,
  eagle_grep: scanFinding, // chain alias -> scan leaked source
  eagle_eye: scanFinding, // chain alias -> scan leaked source
  blitz_scan: scanFinding, // chain alias -> scan leaked source
  source_analysis: scanFinding, // chain alias -> scan leaked source
  browser: browserFinding, // drive a real browser to validate the finding
  browser_devtools: devtoolsFinding, // spawn chrome-devtools-mcp + drive it (network/console/evaluate)
  burp: burpFinding, // auto-detect + verify Burp Suite MCP (SSE handshake + tools/list)
  burp_suite_mcp: burpFinding, // chain alias -> Burp MCP verification
};

/** Concatenate all evidence text from a finding (for hash + sink scanning). */
function findingText(f: Finding): string {
  const parts: string[] = [];
  if (f.source?.name) parts.push(f.source.name);
  if (f.sink?.symbol) parts.push(String(f.sink.symbol));
  const ev = (f as unknown as { evidence?: Array<{ artifacts?: Array<{ content?: unknown }> }> }).evidence ?? [];
  for (const e of ev) {
    for (const a of e.artifacts ?? []) {
      if (typeof a.content === "string") parts.push(a.content);
    }
  }
  return parts.join("\n");
}

function findingUrl(f: Finding): string {
  return (f.target?.host ?? "") + (f.target?.endpoint ?? "");
}

async function verifyFinding(f: Finding): Promise<Record<string, unknown>> {
  const url = findingUrl(f);
  const param = f.source?.name ?? "q";
  const v: StrikeVerdict = await strikeVerify({ url, method: "GET", param });
  return {
    status: v.status,
    marker_reflected: v.marker_reflected,
    control_reflected: v.control_reflected,
    bypass: v.bypass,
    leaked_sinks: (v.leaked_sinks ?? []) as SinkHit[],
  };
}

async function crackFinding(f: Finding): Promise<Record<string, unknown>> {
  const text = findingText(f);
  const hashRe = /(\$2[aby]\$\d+\$[./A-Za-z0-9]{53}|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})/g;
  const hashes = [...new Set(text.match(hashRe) ?? [])].slice(0, 10);
  if (hashes.length === 0) return { hashes_found: 0, note: "no hash-like strings in evidence" };
  const results = [];
  for (const h of hashes) results.push({ hash: h.slice(0, 24) + "…", ...(await crackHash(h)) });
  return { hashes_found: hashes.length, results };
}

function scanFinding(f: Finding): Record<string, unknown> {
  const text = findingText(f);
  const leak = detectSourceLeak(text);
  const sinks = scanSinks(text);
  return { source_leak: leak, sinks_found: sinks.length, sinks };
}

// Data-driven map: a finding's chain/class -> the browser check that validates it.
// This is a lookup table (not hardcoded per-vuln code); the browser tool is the
// SAME for every chain — only the check type is chosen from the finding's class.
const BROWSER_CHECK_BY_CLASS: Array<[RegExp, BrowserCheck]> = [
  [/(xss|ssti|html|script|dom)/i, "dom_xss"],
  [/(redirect|open_redirect|oauth)/i, "open_redirect"],
  [/(csrf)/i, "csrf"],
  [/(auth|login|session|bypass)/i, "auth_bypass"],
];

function inferBrowserCheck(f: Finding): BrowserCheck | null {
  const text = `${f.chain?.id ?? ""} ${f.chain?.name ?? ""} ${f.title ?? ""} ${f.classification?.cwe ?? ""}`.toLowerCase();
  for (const [re, check] of BROWSER_CHECK_BY_CLASS) {
    if (re.test(text)) return check;
  }
  return null;
}

/** Drive a real headless browser to validate the finding (DOM XSS / open redirect /
 * auth bypass / CSRF). The check is chosen from the finding's class via a data map. */
async function browserFinding(f: Finding): Promise<Record<string, unknown>> {
  const check = inferBrowserCheck(f);
  if (!check) return { executed: false, note: "no browser check matches this finding's class — deferred" };
  const target = findingUrl(f);
  const evidence = await browserValidate(check, target);
  return { check_type: check, ...evidence };
}

/** Spawn chrome-devtools-mcp and drive it against the finding's target — a REAL
 * browser session capturing network traffic, console messages, and a JS eval. */
async function devtoolsFinding(f: Finding): Promise<Record<string, unknown>> {
  const target = findingUrl(f);
  if (!target) return { executed: false, note: "no target URL on finding — deferred" };
  const result = await driveChromeDevtools(target);
  return { devtools: true, ...result };
}

/** Auto-detect + verify Burp Suite MCP: check the SSE endpoint is alive, perform
 * the handshake, and list its tools — proving Burp is actually connected rather
 * than returning a connect string that may error at test time. */
async function burpFinding(_f: Finding): Promise<Record<string, unknown>> {
  const result = await driveBurpMCP();
  return { burp: true, ...result };
}

/** Execute every step of a finding's chain. Generic, name-based dispatch — the
 * tool used comes from the chain's tool_hint, resolved against (1) the Blitz MCP
 * finding-tools, (2) the catalog of external tools, (3) manual. No per-vuln or
 * per-category hardcoding: whatever tool the chain names for THIS finding runs. */
export async function executeChainSteps(f: Finding, steps: ChainStepDef[]): Promise<ChainStepResult[]> {
  const results: ChainStepResult[] = [];
  for (const step of steps) {
    const hint = (step.tool_hint ?? "manual").trim();
    const base = { order: step.order, action: step.action, tool_hint: hint || "manual" };
    try {
      const norm = hint.toLowerCase().replace(/[^a-z0-9_]/g, "");
      // 1) Blitz MCP finding tool (resolved by exact name).
      const blitz = BLITZ_FINDING_TOOLS[norm];
      if (blitz) {
        results.push({ ...base, executed: true, outcome: "executed", tool: norm, detail: await blitz(f) });
        continue;
      }
      // 2) Catalog external tool (resolved by name/tag/fuzzy).
      if (toolForHint(hint)) {
        const r = runCatalogTool(hint, findingUrl(f));
        // MCP servers are connected (not one-shot run) — surface the connection
        // string as a deferred step the LLM connects, rather than claiming it ran.
        if (r.kind === "mcp-server") {
          results.push({ ...base, executed: false, outcome: "deferred", tool: String(r.name ?? hint), detail: r });
        } else {
          results.push({ ...base, executed: r.installed === true, outcome: "executed", tool: String(r.name ?? hint), detail: r });
        }
        continue;
      }
      // 3) No tool resolved — defer with the exact action + tool for the LLM.
      results.push({
        ...base,
        executed: false,
        outcome: "deferred",
        detail: `manual step — run '${hint}' to: ${step.action} (success: ${step.success_criteria ?? "n/a"})`,
      });
    } catch (e) {
      results.push({ ...base, executed: false, outcome: "error", detail: String(e) });
    }
  }
  return results;
}
