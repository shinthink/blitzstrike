/** BlitzStrike MCP server — registers all tools against the MCP SDK.
 *
 * 3-tier toolbelt:
 *   BLITZ     — fast attack-surface triage (blitz_scan, blitz_file)
 *   EAGLE-EYE — source-to-sink trace (eagle_eye, eagle_grep, enrich_scan)
 *   STRIKE    — verify + recon + orchestrate (strike_verify, scope_check,
 *               run_engagement, list_chains, fofa_search, nvd_lookup)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";
import {
  scanFile,
  traceFunction,
  grepInFunctions,
  iterSourceFiles,
} from "./scanner.js";
import { fofaSearch, nvdLookup } from "./recon.js";
import {
  scopeCheck,
  enrichScan,
  runEngagement,
  runLiveEngagement,
  listChains,
  formatStatus,
  formatPlanChecklist,
  classifyTarget,
} from "./orchestrator.js";
import {
  toolLookup,
  listTools,
  skillLookup,
  listSkills,
  readSkill,
  ensureTool,
} from "./catalog.js";
import {
  remember as _remember,
  memoryLookup as _memoryLookup,
  listMemory as _listMemory,
  forget as _forget,
  type MemoryType,
} from "./memory.js";
import {
  findManual as _findManual,
  listManuals as _listManuals,
  readPlaybook as _readPlaybook,
  listPlaybooks as _listPlaybooks,
} from "./manuals.js";
import {
  detectWaf as _detectWaf,
  techCorrelation as _techCorrelation,
  cveCorrelation as _cveCorrelation,
  portCorrelation as _portCorrelation,
  fuzzerPayloads as _fuzzerPayloads,
  intelSummary as _intelSummary,
  payloadLookup as _payloadLookup,
  readPayload as _readPayload,
  listPayloadCategories as _listPayloadCategories,
  templateLookup as _templateLookup,
  listAttackVectors as _listAttackVectors,
  attackVectors as _attackVectors,
  bypassLookup as _bypassLookup,
  chainLinks as _chainLinks,
  retryGuidance as _retryGuidance,
  orchestration as _orchestration,
  modelFallback as _modelFallback,
  doctrineMap as _doctrineMap,
  wstgMap as _wstgMap,
  techniqueLookup as _techniqueLookup,
  frameworkTricks as _frameworkTricks,
  resourceLookup as _resourceLookup,
  taxonomy as _taxonomy,
} from "./intel.js";
import { activeScan } from "./active.js";
import { startEngagement as _startEngagement, setPhase as _setPhase, trackHypothesis as _trackHypothesis, engagementStatus as _engagementStatus } from "./engagement.js";
import { analyzeChangedFiles as _analyzeChangedFiles } from "./incremental.js";
import { makeFinding, transition as _transition, canTransition as _canTransition, computeConfidence as _computeConfidence, confidenceLevel as _confidenceLevel, setConfidenceWeights as _setConfidenceWeights, getConfidenceWeights as _getConfidenceWeights, attachEvidence as _attachEvidence, type FindingStatus, type FindingTarget, type Severity, type Finding } from "./finding.js";
import { makeEvidence as _makeEvidence, redactSecrets as _redactSecrets, type EvidenceType } from "./evidence.js";
import { traceDataFlow, groupVariants } from "./dataflow.js";
import { analyzeTaint, taintTree } from "./taint.js";
import { analyzeDataFlow2 } from "./eagle2.js";
import { analyzeDifferential, analyzeDifferentialFiles, analyzeGitDiff } from "./differential.js";
import { listFrameworks, detectFramework, frameworkProfile, scanFramework } from "./frameworks.js";
import { browserValidate, type BrowserCheck } from "./browser.js";
import { browserAgent, detectAuthForm, browserDiagnostics, browserClose, type BrowserOp } from "./browser-agent.js";
import { analyzeTaintUniversal, detectLanguage, listLanguages } from "./universal-taint.js";
import { detectRouteConfusion } from "./route-confusion.js";
import { detectComplexBugs } from "./complex-bugs.js";
import "./adapters.js"; // register language adapters at import time
import { nextSteps } from "./guidance.js";
import { liveRecon } from "./live-recon.js";
import { strikeVerify, resolveFinding as _resolveFinding, type StrikeVerdict } from "./strike.js";
import { cvssAssess, type CvssInput } from "./cvss.js";
import { dedupFindings, uniqueFindings } from "./dedup.js";
import { reportMarkdown, reportJson } from "./report.js";
import { runBenchmark } from "./benchmark.js";
import { runEnterpriseBenchmark } from "./enterprise-benchmark.js";
import { coverageMatrix } from "./coverage.js";
import { checkLatestVersion } from "./update.js";
import { VERSION } from "./version.js";

export function createServer(): McpServer {
  const server = new McpServer(
    {
      name: "blitzstrike",
      version: "1.0.0",
    },
    {
      instructions:
        "Blitz Strike is a universal penetration-testing toolbelt with three tiers — " +
        "BLITZ (reconnaissance / attack-surface mapping), EAGLE-EYE (source-to-sink " +
        "analysis), STRIKE (live validation) — plus a canonical evidence-first finding " +
        "engine and a multi-language taint engine.\\n\\n" +

        "CORE MENTAL MODEL:\\n" +
        "- A scanner hit is a HYPOTHESIS, not a finding. Live verification (or data-flow " +
        "  proof) is the verdict. Never report an unverified hit as a vulnerability.\\n" +
        "- Distinguish REACHABLE from mere PRESENT: a sink is only a finding when tainted " +
        "  input reaches it AND it is not neutralized by a sanitizer and not guarded by an " +
        "  auth gate.\\n\\n" +

        "HOW TO RUN AN AUDIT (start here):\\n" +
        "0. ROUTE BY TARGET. Classify automatically - no need to ask. A URL - with or " +
        "   without http/https - is LIVE (live_recon + the " +
        "   web-hunting doctrine + strike_verify). A filesystem path (exists on disk, " +
        "   or a code extension) is SOURCE audit (source-audit doctrine: blitz_scan + " +
        "   eagle_eye2 + complex_scan/route_scan). TWO DOCTRINES - never mix: live " +
        "   web/API -> web-hunting skill; source tree -> source-audit skill.\\n" +
        "1. RECORD SCOPE. scope_check classifies the target (intel for the report) - " +
        "   it does NOT gate the engagement. No authorization gate: the repo disclaimer " +
        "   places responsibility on the user. Hunt the target you are given.\\n" +
        "2. MAP THE SURFACE (BLITZ). For a source tree use blitz_scan (tree) or blitz_file " +
        "   (single file) then enrich_scan to match sinks to escalation chains. For a live " +
        "   URL use live_recon for a full pass (fingerprint/WAF/tech/version/crawler/params/" +
        "   subdomains/API endpoints/intel correlation) — it returns next_steps. active_scan " +
        "   is the lighter alternative. Both record scope internally.\\n" +
        "3. TRACE REACHABILITY (EAGLE-EYE). For every sink, determine whether attacker " +
        "   input actually reaches it:\\n" +
        "   - PHP/JS/TS/Python/Java source: taint_file (auto-detects language) or " +
        "     taint_scan/taint_tree (PHP AST). list_languages shows what's supported.\\n" +
        "   - Any language: trace_data_flow (window heuristic) and eagle_eye/eagle_grep " +
        "     (function-scoped view of sinks + auth gates). Beyond taint: route_scan (route confusion / dispatch abuse / batch forwarding) and complex_scan (deserialization->POP, type juggling, mass assignment, prototype pollution, CRLF/header injection, path confusion) catch classes plain taint misses.\\n" +
        "   A sink counts only if tainted input reaches it unsanitized and unguarded.\\n" +
        "4. VALIDATE (STRIKE). Confirm live with strike_verify using a MARKER plus a " +
        "   NEGATIVE CONTROL plus a BASELINE. The verdict is deterministic: marker " +
        "   reflected AND control inert = confirmed; both reflected = false_positive; " +
        "   marker not reflected = unconfirmed. Feed the verdict to strike_resolve to " +
        "   advance the finding lifecycle (hypothesis->validating->confirmed). Use " +
        "   read_tool_manual for the exploit tool's manual, payload_lookup for payloads, " +
        "   detect_waf/tech_correlation for context.\\n" +
        "5. RECORD + REPORT. Create a canonical finding with finding_create, advance it " +
        "   through the lifecycle with finding_transition, attach confidence_score, and " +
        "   redact any secrets before persisting. Only report findings that survived " +
        "   verification.\\n\\n" +

        "SUPPORTING LAYERS:\\n" +
        "- run_engagement: ONE call does the whole audit (no babysitting). Source path -> " +
        "  full static pipeline + inline report (markdown/JSON/SARIF). URL target -> " +
        "  autonomous live marker sweep + confirmed findings + report. Prefer this first.\\n" +
        "- list_chains: 57 escalation chains (source -> sink -> impact).\\n" +
        "- list_languages / taint_file: multi-language taint (PHP, JS/TS, Python, Java).\\n" +
        "- tool_lookup / ensure_tool / list_tools: 130-tool catalog, auto-install.\\n" +
        "- read_playbook / list_playbooks: 17 engagement playbooks (web-app, api-security, " +
        "  source-code-audit, active-directory, mobile, external-attack-surface, ...).\\n" +
        "- skill_lookup / read_skill / list_skills: 39 skills (7 bs-* agent doctrine: " +
        "  orchestrate, scope, source-audit, web-hunting, verify, review, report; + " +
        "  technique playbooks: WP/PHP 0-day, AD, malware, mobile, cloud).\\n" +
        "- read_tool_manual / list_manuals: 317 tool manuals (sqlmap, nmap, commix, ...).\\n" +
        "- payload_lookup / read_payload: 66 payload collections (sqli, xss, ssti, xxe, lfi).\\n" +
        "- detect_waf / tech_correlation / cve_correlation / port_correlation: signature " +
        "  + correlation intelligence.\\n" +
        "- nvd_lookup / fofa_search: CVE lookup + asset reconnaissance (FOFA needs env creds).\\n" +
        "- remember / memory_lookup / memory_list: persist + recall verified knowledge.\\n\\n" +

        "RESOURCE MAP (know what to reach for):\\n" +
        "- ORCHESTRATION = the engagement framework. orchestration() returns the " +
        "  lifecycle (scope->recon->analyze->deep->verify->report, each with " +
        "  entry/exit criteria) + sub-agent team + handoff contract + termination " +
        "  criteria. Load it at engagement start.\\n" +
        "- TOOL = acts (scan, taint, verify, record, correlate). Call it to DO something.\\n" +
        "- PLAYBOOK = campaign plan for a target TYPE. read_playbook(web-application) " +
        "  BEFORE a full engagement of that type.\\n" +
        "- SKILL = procedure doctrine. Load the bs-* skill for the phase you are on " +
        "  (orchestrate, scope, web-hunting for LIVE, source-audit for SOURCE, verify, " +
        "  review, report); load a technique skill for the specific technique.\\n" +
        "- MANUAL = deep reference for ONE tool. read_tool_manual right before using it.\\n" +
        "- CATALOG = external tools (130: sqlmap, nmap, nuclei, ffuf, ysoserial, ...). " +
        "  Blitz Strike's OWN tools find + verify; the catalog is for deeper EXTERNAL " +
        "  exploitation/enumeration. After your own analysis confirms a finding, run " +
        "  tool_lookup -> ensure_tool (auto-install) -> read_tool_manual to drive the " +
        "  external tool that demonstrates impact.\\n" +
        "- PAYLOAD = attack payloads for a class. payload_lookup before crafting a probe.\\n" +
        "- INTELLIGENCE = knowledge. list_attack_vectors (34 categories) maps the " +
        "  full surface during RECON; list_chains (57) turns a finding into impact; " +
        "  chain_links composes chains for complex bugs; bypass_lookup when blocked; " +
        "  payload_lookup when crafting a probe. technique_lookup(cls) returns the " +
        "  DETAILED methodology + tricks for a vulnerability class (ssrf, ssti, " +
        "  jwt, deserialization, ...) - load before testing a class. wstg_map maps " +
        "  an OWASP category to coverage; taxonomy maps findings to standard IDs " +
        "  (OWASP Top 10 / API Top 10 / CWE / ASVS); doctrine_map shows how everything links.\\n\\n" +

        "NO-BABYSITTING (while scanning + testing):\\n" +
        "- Scan the WHOLE surface before reporting - every file, entry point, and sink. " +
        "  Do not stop after the first hit to ask; keep enumerating the full tree.\\n" +
        "- Test every hypothesis through its full verification cycle - vary probes on " +
        "  failure, apply bypasses when blocked, keep going. Do not pause to ask.\\n" +
        "- Persist through partial results: a scan that surfaces few sinks is NOT done - " +
        "  widen the surface, escalate detectors, dig into each reachable sink.\\n" +
        "- Only surface to the user when: the target is genuinely ambiguous, a " +
        "  destructive or DoS action needs explicit consent, or the engagement is complete.\\n\\n" +
        "PERSISTENCE (complex bugs - do not give up):\\n" +
        "- On any failure (empty output, blocked probe, failed sub-agent/model), call " +
        "  retry_guidance(signal) for concrete recovery actions before giving up.\\n" +
        "- On a model/sub-agent error (rate-limit, quota, timeout, 5xx, auth, " +
        "  unavailable), model_fallback(signal) classifies it and returns the exact " +
        "  recovery (retry+backoff / fall back / shrink scope / fix credentials / " +
        "  abort). Do not fall back blindly - the class decides.\\n" +
        "- One failed probe != not vulnerable. Vary: alternative sinks, other params, " +
        "  encoding/case/whitespace bypasses, different injection context.\\n" +
        "- Empty output != no findings. Re-run (server may be stale after an upgrade - " +
        "  /reload-mcp), or escalate to route_scan / complex_scan for classes taint " +
        "  misses (POP chains, type juggling, mass assignment, route confusion).\\n" +
        "- A 'sanitized' sink may not be safe. Challenge the sanitizer: loose == vs ===, " +
        "  missing EXTR_SKIP, int cast truncation, weak regex.\\n" +
        "- An unconfirmed hypothesis is KEPT as hypothesis - try alternate verification, " +
        "  then let adversarial review decide.\\n" +
        "- Complex chains (deserialization->POP, LFI->RCE) need the FULL chain traced, " +
        "  not just the first sink.\\n\n" +
        "- When a probe is BLOCKED by a WAF/filter/sanitizer, call bypass_lookup(defense) " +
        "  for concrete techniques (encoding, case, comment insertion, chunked, null byte, " +
        "  double-encoding, verb tampering, header spoofing) and apply them - do not give up.\\n" +
        "- CHAIN findings: a low-severity finding may escalate — do not assume it is the " +
        "  end of the story. list_chains / chain_links show whether it composes into a " +
        "  multi-stage chain (e.g. SSRF->metadata, SQLi->RCE, LFI->RCE, upload->shell). " +
        "  Check before concluding, and do not overclaim an escalation that is not there.\\n\\n" +
        "- Complex bugs chain ACROSS chains: after confirming one chain, chain_links " +
        "  shows what follows (SSRF->metadata then default-creds->pivot via stolen IAM). " +
        "  Trace the full composition, not just a single chain.\\n\\n" +
        "HYPOTHESIS EXPANSION (from each finding, enumerate + verify every follow-up):\\n" +
        "- A confirmed finding is the START, not the end. From each one, enumerate " +
        "  the follow-ups: ESCALATE (list_chains + chain_links), CHAIN (chain_links " +
        "  from->to), BYPASS (bypass_lookup), PIVOT (new endpoints/sinks now reachable).\\n" +
        "- Every follow-up (this might happen, this could chain, maybe bypassable) is " +
        "  a HYPOTHESIS, not a finding. Verify EACH via strike_verify (marker + negative " +
        "  control) before it enters the report.\\n" +
        "- Never report speculation: might / could / possibly live in the " +
        "  hypothesis list, never in the report. Every report line is a verified fact.\\n\\n" +

        "PROFESSIONAL JUDGMENT (act like a senior tester, not a checklist runner):\\n" +
        "- PRIORITIZE by severity, computed deterministically with cvss_score (impact x " +
        "  exploitability) and weighted by escalation potential (chain_links). Do NOT rank " +
        "  by bug class - a critical stored XSS that yields account takeover outranks an " +
        "  unreachable blind RCE. Weight by the engagement context (which asset/data is " +
        "  most sensitive for THIS target).\\n" +
        "- Recognize dead ends: if a branch yields nothing after a few varied probes, " +
        "  note it and move on. Do not tunnel-vision one sink at the expense of the rest.\\n" +
        "- Live-test with care: respect rate limits, do not lock accounts, do not " +
        "  trigger DoS. Test non-destructively and prove impact with the smallest payload.\\n" +
        "- Know when done: stop when the termination criteria are met, not when you feel " +
        "  tired. A thorough audit over a rushed one, every time.\\n\\n" +
        "IRON RULES:\\n" +
        "- No authorization gate - the repo disclaimer places responsibility on the " +
        "  user. Hunt the target you are given (like nmap/sqlmap/Burp, which do not " +
        "  ask). The one hard stop: malicious/third-party infra (cari pelaku) - hold/static.\\n" +
        "  need finer control.",
    },
  );

  // ---- BLITZ ----
  server.registerTool(
    "blitz_scan",
    {
      title: "BLITZ scan",
      description:
        "BLITZ: scan a source tree for unauth entry points + dangerous sinks with file:line refs.",
      inputSchema: {
        path: z.string().describe("Directory to scan"),
        max_files: z.number().int().optional().describe("Max files (default 5000)"),
      },
    },
    async ({ path, max_files }) => {
      const files = iterSourceFiles(path, max_files ?? 5000);
      const results = files.map((f) => scanFile(f));
      const endpoints = results.flatMap((r) =>
        r.endpoints.map((e) => ({ file: r.file, line: e.line, hook: e.hook })),
      );
      const sinks = results.flatMap((r) =>
        r.sinks.map((s) => ({ file: r.file, line: s.line, sink: s.sink, class: s.class })),
      );
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              root: path,
              files_scanned: files.length,
              endpoints,
              sinks,
            }),
          },
        ],
      };
    },
  );

  server.registerTool(
    "blitz_file",
    {
      title: "BLITZ single-file scan",
      description: "BLITZ: scan a single source file for entry points + sinks.",
      inputSchema: {
        path: z.string().describe("File to scan"),
      },
    },
    async ({ path }) => {
      const r = scanFile(path);
      return {
        content: [{ type: "text", text: JSON.stringify(r) }],
      };
    },
  );

  // ---- EAGLE-EYE ----
  server.registerTool(
    "eagle_eye",
    {
      title: "EAGLE-EYE trace",
      description:
        "EAGLE-EYE: return a function's full body, sinks in scope, and auth gates in scope.",
      inputSchema: {
        path: z.string().describe("File path"),
        symbol: z.string().describe("Function/method name to locate"),
      },
    },
    async ({ path, symbol }) => {
      const r = traceFunction(path, symbol);
      return {
        content: [{ type: "text", text: JSON.stringify(r) }],
      };
    },
  );

  server.registerTool(
    "eagle_grep",
    {
      title: "EAGLE-EYE precision grep",
      description:
        "EAGLE-EYE: report a sink ONLY inside a function body, flagged guarded/un-guarded (anti-grep-monkey).",
      inputSchema: {
        path: z.string().describe("Directory to search"),
        sink: z.string().describe("Sink token to find (e.g. 'move_uploaded_file(')"),
        max_hits: z.number().int().optional().describe("Max hits (default 50)"),
      },
    },
    async ({ path, sink, max_hits }) => {
      const hits = grepInFunctions(path, sink, max_hits ?? 50);
      return {
        content: [{ type: "text", text: JSON.stringify(hits) }],
      };
    },
  );

  server.registerTool(
    "enrich_scan",
    {
      title: "BLITZ+EAGLE-EYE chain enrichment",
      description:
        "Scan a source tree AND match detected sinks to escalation chains (chains.json).",
      inputSchema: {
        path: z.string().describe("Directory to scan"),
        max_files: z.number().int().optional().describe("Max files (default 2000)"),
      },
    },
    async ({ path, max_files }) => {
      const r = enrichScan(path, max_files ?? 2000);
      return {
        content: [{ type: "text", text: JSON.stringify(r) }],
      };
    },
  );

  // ---- STRIKE ----
  server.registerTool(
    "strike_verify",
    {
      title: "STRIKE live verification",
      description:
        "STRIKE: live HTTP verification with marker + negative control + baseline. Verdict: confirmed (marker reflected, control NOT) / false_positive (both reflected) / unconfirmed (marker not reflected) / blocked. Returns redacted SHA-256-tagged evidence. " +
        "USE WHEN: you have a hypothesis and need to prove (or refute) it live. " +
        "NEXT: feed the verdict to strike_resolve to advance the finding's lifecycle.",
      inputSchema: {
        url: z.string().describe("Target URL"),
        method: z.enum(["GET", "POST"]).optional().describe("HTTP method"),
        data: z.string().optional().describe("POST body template; a literal {{MARKER}} is replaced"),
        headers: z.string().optional().describe("JSON object of extra headers"),
        marker: z.string().optional().describe("Unique string the payload should reflect (defaults to a random token)"),
        control: z.string().optional().describe("Benign lookalike for the negative control (defaults to a random token)"),
        param: z.string().optional().describe("Query/body param name to inject into (default 'q')"),
        timeout: z.number().int().optional().describe("Timeout seconds (default 15)"),
      },
    },
    async ({ url, method, data, headers, marker, control, param, timeout }) => {
      let hdrs: Record<string, string> = {};
      try { hdrs = headers ? JSON.parse(headers) : {}; } catch { /* ignore */ }
      const verdict = await strikeVerify({
        url,
        method: method ?? "GET",
        data,
        headers: hdrs,
        marker,
        control,
        param,
        timeout: timeout ? timeout * 1000 : undefined,
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...verdict,
            next_steps: [
              `Verdict: ${verdict.status} — ${verdict.reason}`,
              verdict.status === "confirmed"
                ? "Confirmed. Attach to the finding with strike_resolve, then record evidence (finding_create already carried SHA-256 artifacts)."
                : verdict.status === "false_positive"
                  ? "False positive. Reject the finding via strike_resolve to close it out."
                  : "Not confirmed. Refine the payload or trace reachability (taint_file / eagle_eye) before re-validating.",
            ],
          }),
        }],
      };
    },
  );

  server.registerTool(
    "strike_resolve",
    {
      title: "Resolve a finding from a STRIKE verdict",
      description:
        "STRIKE+FINDINGS: take a canonical Finding and a STRIKE verdict, and advance the lifecycle end-to-end — hypothesis->validating->confirmed (marker reflected, control inert) or ->false_positive/blocked/unconfirmed. Returns the updated finding with evidence + recomputed confidence.",
      inputSchema: {
        finding: z.string().describe("JSON of the canonical Finding object (from finding_create)"),
        verdict: z.string().describe("JSON of the STRIKE verdict (from strike_verify)"),
      },
    },
    async ({ finding, verdict }) => {
      let f: Finding;
      let v: StrikeVerdict;
      try { f = JSON.parse(finding); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid finding JSON" }) }] }; }
      try { v = JSON.parse(verdict); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid verdict JSON" }) }] }; }
      const updated = _resolveFinding(f, v);
      return { content: [{ type: "text", text: JSON.stringify(updated) }] };
    },
  );

  server.registerTool(
    "scope_check",
    {
      title: "STRIKE scope classification",
      description:
        "STRIKE: classify a target against scope (intel for the report — not a gate). Exclusion-aware, mode-aware.",
      inputSchema: {
        target: z.string().describe("Target URL/host"),
        scope: z.string().optional().describe("In-scope patterns; '-' prefix = exclusion"),
        mode: z.string().optional().describe("Engagement mode (bug-bounty/ctf/offensive/...)"),
      },
    },
    async ({ target, scope, mode }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(scopeCheck(target, scope ?? "", mode ?? "bug-bounty")) }],
      };
    },
  );

  server.registerTool(
    "active_scan",
    {
      title: "STRIKE live black-box scan",
      description:
        "STRIKE: live black-box scan of a URL — fingerprint, WAF detection, tech correlation, endpoint discovery. No authorization gate (the repo disclaimer covers responsibility).",
      inputSchema: {
        target: z.string().describe("Target URL/host to scan"),
        scope: z.string().optional().describe("In-scope patterns (required for strict modes)"),
        mode: z.string().optional().describe("Engagement mode (bug-bounty/ctf/offensive/...)"),
      },
    },
    async ({ target, scope, mode }) => {
      const gate = scopeCheck(target, scope ?? "", mode ?? "bug-bounty");
      // No authorization gate — the repo disclaimer places responsibility on the user.
      const allowed = true;
      const result = await activeScan(target, scope ?? "", mode ?? "bug-bounty", allowed);
      return {
        content: [{ type: "text", text: JSON.stringify({ scope_gate: gate, ...result }) }],
      };
    },
  );

  server.registerTool(
    "live_recon",
    {
      title: "Full live reconnaissance (multi-phase)",
      description:
        "STRIKE: comprehensive live recon — fingerprint, WAF, tech+version detection, crawler (links/scripts/robots/sitemap), parameter discovery, subdomain enumeration (crt.sh), API endpoint discovery, and intel correlation (tech/CVE/port/payloads/templates). " +
        "Returns next_steps so you know exactly what to do after each result. " +
        "USE WHEN: you have a live URL and need to map its full attack surface before source analysis or exploitation.",
      inputSchema: {
        target: z.string().describe("Target URL/host"),
      },
    },
    async ({ target }) => {
      const result = await liveRecon(target, true);
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
      };
    },
  );

  server.registerTool(
    "run_engagement",
    {
      title: "STRIKE full engagement",
      description:
        "STRIKE: run a full audit in ONE call (no babysitting). Source path -> triage -> chain enrichment -> findings -> inline report (markdown+JSON+SARIF). URL target -> autonomous live marker sweep (strike_verify per parameter) -> confirmed findings -> inline report.",
      inputSchema: {
        target: z.string().describe("Source path or URL"),
        scope: z.string().optional().describe("Scope (for URL targets)"),
        mode: z.string().optional().describe("Engagement mode"),
        max_files: z.number().int().optional().describe("Max files (default 2000)"),
        remember: z.boolean().optional().describe("Auto-capture matched chains to memory (default true)"),
      },
    },
    async ({ target, scope, mode, max_files, remember }) => {
      // Auto-classify: source path on disk -> static pipeline; live host ->
      // autonomous marker sweep. Scheme-less domains/IPs get https:// prepended.
      const cls = classifyTarget(target);
      const r = cls.kind === "live"
        ? await runLiveEngagement(cls.target, scope ?? "", mode ?? "bug-bounty")
        : runEngagement(cls.target, scope ?? "", mode ?? "bug-bounty", max_files ?? 2000, remember ?? true);
      // Surface the "orchestrator in control" banner as a standalone text block
      // (first), so it visibly appears in the client terminal rather than being
      // buried inside the JSON result.
      const banner = typeof r.banner === "string" ? r.banner : "";
      const planText = Array.isArray(r.plan) && r.plan.length ? `\n\nplan:\n${formatPlanChecklist(r.plan)}` : "";
      const statusLine =
        r.status === "BLOCKED"
          ? `✋ BLOCKED — ${r.reason ?? "scope required"}`
          : `→ ${Array.isArray(r.findings) ? r.findings.length : 0} finding(s), status=${r.status ?? "COMPLETE"}`;
      return {
        content: [
          { type: "text", text: banner ? `${banner}${planText}\n\n${statusLine}` : statusLine },
          { type: "text", text: JSON.stringify(r) },
        ],
      };
    },
  );

  server.registerTool(
    "blitz_status",
    {
      title: "Engagement progress banner",
      description:
        "Format a terminal-friendly live progress snapshot of the running engagement — current stage (of the scope→recon→analyze→verify→review→report pipeline), finding counts, and task status. Call it to announce progress to the user as you drive the audit.",
      inputSchema: {
        phase: z.string().optional().describe("Current stage: scope/recon/analyze/verify/review/report"),
        findings: z.record(z.string(), z.number()).optional().describe("Finding counts, e.g. {detected:4,hypothesis:2,confirmed:1,false_positive:0}"),
        tasks: z.array(z.object({ id: z.string(), objective: z.string(), status: z.string() })).optional().describe("Task list with status"),
      },
    },
    async ({ phase, findings, tasks }) => {
      return {
        content: [{ type: "text", text: formatStatus({ phase, findings, tasks }) }],
      };
    },
  );

  server.registerTool(
    "list_chains",
    {
      title: "STRIKE list chains",
      description: "STRIKE: list all escalation chains in the data layer (chains.json).",
      inputSchema: {},
    },
    async () => {
      return {
        content: [{ type: "text", text: JSON.stringify(listChains()) }],
      };
    },
  );

  server.registerTool(
    "fofa_search",
    {
      title: "FOFA asset search",
      description: "STRIKE: search the FOFA asset index (needs FOFA_EMAIL + FOFA_KEY).",
      inputSchema: {
        query: z.string().describe("FOFA query"),
        size: z.number().int().optional().describe("Result size (default 20)"),
        fields: z.string().optional().describe("Comma-separated fields"),
      },
    },
    async ({ query, size, fields }) => {
      const r = await fofaSearch(query, size ?? 20, fields ?? "host,ip,port,protocol,title,server");
      return {
        content: [{ type: "text", text: JSON.stringify(r) }],
      };
    },
  );

  server.registerTool(
    "nvd_lookup",
    {
      title: "NVD CVE lookup",
      description: "STRIKE: look up a CVE from NVD 2.0 (no key required).",
      inputSchema: {
        cve_id: z.string().describe("CVE ID (e.g. CVE-2026-61424)"),
      },
    },
    async ({ cve_id }) => {
      const r = await nvdLookup(cve_id);
      return {
        content: [{ type: "text", text: JSON.stringify(r) }],
      };
    },
  );

  // ---- CATALOG (breadth layer: tools + skills) ----
  server.registerTool(
    "tool_lookup",
    {
      title: "Look up a security tool",
      description:
        "Look up a tool in tools-catalog.json (command + flags + install + check).",
      inputSchema: {
        name: z.string().describe("Tool name (e.g. sqlmap, nuclei, wpscan)"),
      },
    },
    async ({ name }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(toolLookup(name)) }],
      };
    },
  );

  server.registerTool(
    "list_tools",
    {
      title: "List all tools",
      description: "List all tools in the catalog, grouped by category.",
      inputSchema: {},
    },
    async () => {
      return {
        content: [{ type: "text", text: JSON.stringify(listTools()) }],
      };
    },
  );

  server.registerTool(
    "skill_lookup",
    {
      title: "Look up a skill playbook",
      description:
        "Search the skills/ knowledge base for a relevant playbook by topic.",
      inputSchema: {
        topic: z.string().describe("Topic (e.g. 'hmac', 'unserialize', 'waf bypass')"),
      },
    },
    async ({ topic }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(skillLookup(topic)) }],
      };
    },
  );

  server.registerTool(
    "list_skills",
    {
      title: "List all skills",
      description: "List all skill playbooks in the knowledge base.",
      inputSchema: {},
    },
    async () => {
      return {
        content: [{ type: "text", text: JSON.stringify(listSkills()) }],
      };
    },
  );

  server.registerTool(
    "read_skill",
    {
      title: "Read a skill playbook",
      description: "Read the full content of a skill playbook by name.",
      inputSchema: {
        name: z.string().describe("Skill name (e.g. 'wp-empty-hmac-csrf-bypass')"),
      },
    },
    async ({ name }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(readSkill(name)) }],
      };
    },
  );

  server.registerTool(
    "ensure_tool",
    {
      title: "Ensure a tool is installed",
      description:
        "Check if a catalog tool is installed; if not, install it (auto-install).",
      inputSchema: {
        name: z.string().describe("Tool name to ensure"),
      },
    },
    async ({ name }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(ensureTool(name)) }],
      };
    },
  );

  // ---- MEMORY (long-term knowledge, append-only) ----
  server.registerTool(
    "remember",
    {
      title: "Remember a piece of knowledge",
      description:
        "Save a reusable insight to long-term memory (deduped). verified=true only if marker reflected + negative control inert.",
      inputSchema: {
        topic: z.string().describe("Short topic key (e.g. 'hmac-empty-key-forgery')"),
        content: z.string().describe("The knowledge: pattern, bypass, or lesson"),
        type: z.enum(["skill", "pattern", "bypass", "signature", "lesson", "engagement"]).optional().describe("Entry type"),
        tags: z.array(z.string()).optional().describe("Tags for search"),
        source: z.string().optional().describe("Where it came from (manual/engagement)"),
        verified: z.boolean().optional().describe("true only if live-verified"),
      },
    },
    async ({ topic, content, type, tags, source, verified }) => {
      const r = _remember(topic, content, (type as MemoryType) ?? "lesson", tags ?? [], source ?? "manual", verified ?? false);
      return { content: [{ type: "text", text: JSON.stringify(r) }] };
    },
  );

  server.registerTool(
    "memory_lookup",
    {
      title: "Search long-term memory",
      description: "Search memory by topic/tag/content, scored by relevance.",
      inputSchema: {
        query: z.string().describe("Search query"),
      },
    },
    async ({ query }) => {
      return { content: [{ type: "text", text: JSON.stringify(_memoryLookup(query)) }] };
    },
  );

  server.registerTool(
    "memory_list",
    {
      title: "List long-term memory",
      description: "List all memory entries, grouped by type.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_listMemory()) }] };
    },
  );

  server.registerTool(
    "memory_forget",
    {
      title: "Forget a memory entry",
      description:
        "MEMORY: remove a memory entry by id (append-only store; 'forget' = tombstone).",
      inputSchema: { id: z.string().describe("Memory entry id (from memory_list)") },
    },
    async ({ id }) => {
      return { content: [{ type: "text", text: JSON.stringify(_forget(id)) }] };
    },
  );

  // ---- MANUALS (deep tool reference + playbooks) ----
  server.registerTool(
    "read_tool_manual",
    {
      title: "Read a tool manual",
      description:
        "Read the full deep reference manual for a security tool (317 manuals from kali-pentest, Apache-2.0).",
      inputSchema: {
        name: z.string().describe("Tool name (e.g. sqlmap, ffuf, nmap, ghidra)"),
      },
    },
    async ({ name }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(_findManual(name)) }],
      };
    },
  );

  server.registerTool(
    "list_manuals",
    {
      title: "List all manuals",
      description: "List all tool manuals and playbooks available.",
      inputSchema: {},
    },
    async () => {
      return {
        content: [{ type: "text", text: JSON.stringify(_listManuals()) }],
      };
    },
  );

  server.registerTool(
    "read_playbook",
    {
      title: "Read an engagement playbook",
      description:
        "Read a full engagement playbook (web-app, api-security, active-directory, forensics-triage, etc.).",
      inputSchema: {
        name: z.string().describe("Playbook name (e.g. 'web-application', 'api-security')"),
      },
    },
    async ({ name }) => {
      return {
        content: [{ type: "text", text: JSON.stringify(_readPlaybook(name)) }],
      };
    },
  );

  server.registerTool(
    "list_playbooks",
    {
      title: "List all playbooks",
      description: "List all engagement playbooks available.",
      inputSchema: {},
    },
    async () => {
      return {
        content: [{ type: "text", text: JSON.stringify(_listPlaybooks()) }],
      };
    },
  );

  // ---- INTELLIGENCE (WAF + tech/CVE/port correlations + fuzzer data) ----
  server.registerTool(
    "detect_waf",
    {
      title: "Detect WAF from response headers",
      description:
        "INTEL: detect a WAF from HTTP response headers/body (100+ signatures).",
      inputSchema: {
        headers: z.string().describe("JSON object of response headers"),
        body: z.string().optional().describe("Response body (for body-signature detection)"),
      },
    },
    async ({ headers, body }) => {
      let hdrs: Record<string, string> = {};
      try { hdrs = JSON.parse(headers); } catch { hdrs = {}; }
      return { content: [{ type: "text", text: JSON.stringify(_detectWaf(hdrs, body ?? "")) }] };
    },
  );

  server.registerTool(
    "tech_correlation",
    {
      title: "Correlate tech to vulns/CVEs",
      description: "INTEL: given a technology, return known vulns + CVEs + paths.",
      inputSchema: {
        tech: z.string().describe("Technology (wordpress, drupal, nginx, jenkins, ...)"),
      },
    },
    async ({ tech }) => {
      return { content: [{ type: "text", text: JSON.stringify(_techCorrelation(tech)) }] };
    },
  );

  server.registerTool(
    "cve_correlation",
    {
      title: "Correlate CVE to targets",
      description: "INTEL: given a CVE, return product + affected targets + severity.",
      inputSchema: {
        cve: z.string().describe("CVE ID (e.g. CVE-2021-44228)"),
      },
    },
    async ({ cve }) => {
      return { content: [{ type: "text", text: JSON.stringify(_cveCorrelation(cve)) }] };
    },
  );

  server.registerTool(
    "port_correlation",
    {
      title: "Correlate port to service/attack",
      description: "INTEL: given a port, return service + attack vectors (103 ports).",
      inputSchema: {
        port: z.string().describe("Port number (e.g. '22', '445')"),
      },
    },
    async ({ port }) => {
      return { content: [{ type: "text", text: JSON.stringify(_portCorrelation(port)) }] };
    },
  );

  server.registerTool(
    "fuzzer_payloads",
    {
      title: "Fuzzer payloads + chain rules",
      description: "INTEL: fuzzing payload collections + vulnerable patterns + chain rules.",
      inputSchema: {
        category: z.string().optional().describe("Specific fuzzer category (optional)"),
      },
    },
    async ({ category }) => {
      return { content: [{ type: "text", text: JSON.stringify(_fuzzerPayloads(category)) }] };
    },
  );

  server.registerTool(
    "intel_summary",
    {
      title: "Intelligence layer summary",
      description: "INTEL: counts of WAF sigs, tech/CVE/port correlations, fuzzer categories, and attack vectors.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_intelSummary()) }] };
    },
  );

  server.registerTool(
    "list_attack_vectors",
    {
      title: "List the attack-vector taxonomy",
      description:
        "BLITZ: list the full web attack-vector taxonomy (34 categories, 588 vectors) grouped by category, for attack-surface mapping.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_listAttackVectors()) }] };
    },
  );

  server.registerTool(
    "attack_vectors",
    {
      title: "Enumerate attack vectors for a category",
      description:
        "BLITZ: return the full vector list for one attack category (e.g. 'ssrf', 'business logic', 'ai/llm') so a driving agent covers the whole attack surface.",
      inputSchema: {
        category: z.string().describe("Category id or fuzzy title (e.g. ssrf, business_logic, ai/llm)"),
      },
    },
    async ({ category }) => {
      return { content: [{ type: "text", text: JSON.stringify(_attackVectors(category)) }] };
    },
  );

  server.registerTool(
    "payload_lookup",
    {
      title: "Look up exploit payloads",
      description: "INTEL: find a payload collection (66 categories from PayloadsAllTheThings).",
      inputSchema: {
        topic: z.string().describe("Payload topic (xss, sqli, ssrf, command-injection, jwt, ...)"),
      },
    },
    async ({ topic }) => {
      return { content: [{ type: "text", text: JSON.stringify(_payloadLookup(topic)) }] };
    },
  );

  server.registerTool(
    "bypass_lookup",
    {
      title: "Look up bypass techniques",
      description:
        "INTEL: return bypass techniques for a defense that is blocking a probe. Pass a defense/context (waf, firewall, filter, sanitizer, blacklist, 403/401, auth, captcha, rate limit) and get concrete techniques (encoding, case, comment insertion, chunked, null byte, double-encoding, verb tampering, header spoofing, ...) with examples. Use it when a strike_verify probe is blocked instead of giving up.",
      inputSchema: {
        defense: z.string().optional().describe("Defense/context to bypass: waf, filter, sanitizer, blacklist, 403/401/auth, captcha, rate limit. Omit to list all categories."),
      },
    },
    async ({ defense }) => {
      return { content: [{ type: "text", text: JSON.stringify(_bypassLookup(defense)) }] };
    },
  );

  server.registerTool(
    "chain_links",
    {
      title: "Chain-to-chain composition",
      description:
        "INTEL: return how escalation chains compose — which chain naturally follows another (e.g. SSRF->cloud-metadata then default-creds->internal-pivot via stolen IAM). Use it after confirming a chain to see what a complex bug chains into next, instead of stopping at one chain.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_chainLinks()) }] };
    },
  );

  server.registerTool(
    "retry_guidance",
    {
      title: "Failure recovery guidance",
      description:
        "INTEL: return structured recovery actions for a failure mode instead of giving up. Pass a signal (empty output, blocked, sanitized, subagent failed, model failed/rate-limit, unconfirmed, low severity) and get concrete next actions (reload-mcp, escalate detector, bypass_lookup, challenge sanitizer, re-delegate, fall back model, chain_links).",
      inputSchema: {
        signal: z.string().optional().describe("Failure signal: empty output / blocked / sanitized / subagent failed / model failed / unconfirmed / low severity. Omit to list all modes."),
      },
    },
    async ({ signal }) => {
      return { content: [{ type: "text", text: JSON.stringify(_retryGuidance(signal)) }] };
    },
  );

  server.registerTool(
    "orchestration",
    {
      title: "Orchestration framework",
      description:
        "INTEL: return the orchestration framework — the engagement lifecycle (scope→recon→analyze→deep→verify→report, each with entry/exit criteria), the sub-agent team (roles + tools + returns), the handoff contract, and the termination criteria. Load this at engagement start; pass a phase/role id (scope, recon, analyze, deep, verify, report, or team/handoff/termination) to focus.",
      inputSchema: {
        part: z.string().optional().describe("Optional focus: lifecycle / team / handoff / termination, or a phase id (scope, recon, analyze, deep, verify, report) or role id (recon, taint, deep, verify)."),
      },
    },
    async ({ part }) => {
      return { content: [{ type: "text", text: JSON.stringify(_orchestration(part)) }] };
    },
  );

  server.registerTool(
    "model_fallback",
    {
      title: "Model/sub-agent failure recovery",
      description:
        "ORCHESTRATION: classify a model or sub-agent failure and decide the recovery. Pass the error text (rate limit / 429 / quota / context length / timeout / 500 / auth / connection / unavailable / aborted) and get the error class, whether it is retryable, whether to back off, the per-class action (retry+backoff vs fall back vs shrink scope vs fix credentials vs abort), the fallback chain, and the backoff schedule.",
      inputSchema: {
        signal: z.string().optional().describe("The error text or signal. Omit to list all error classes + the fallback chain."),
      },
    },
    async ({ signal }) => {
      return { content: [{ type: "text", text: JSON.stringify(_modelFallback(signal)) }] };
    },
  );

  server.registerTool(
    "doctrine_map",
    {
      title: "Interconnected doctrine map",
      description:
        "ORCHESTRATION: return the interconnected doctrine map — each phase (scope→recon→analyze→deep→verify→report) with its skill, OWASP WSTG category, tools, and data; plus the cross-cutting moments (blocked→bypass_lookup, finding→list_chains/chain_links, probe→payload_lookup, failed→model_fallback/retry_guidance, done→engagement_status). Load to see how the pieces link.",
      inputSchema: {
        part: z.string().optional().describe("Optional focus: a phase id (scope, recon, analyze, deep, verify, report) or 'cross_cutting'."),
      },
    },
    async ({ part }) => {
      return { content: [{ type: "text", text: JSON.stringify(_doctrineMap(part)) }] };
    },
  );

  server.registerTool(
    "wstg_map",
    {
      title: "OWASP WSTG -> Blitz coverage map",
      description:
        "INTEL: map an OWASP WSTG category (WSTG-INFO, WSTG-INPV, WSTG-BUSL, WSTG-CLNT, WSTG-APIT, ...) to the Blitz Strike skill, phase, tools, and data that covers it, including the high-value advanced tests where Blitz has a specific deterministic capability. Use to ground the engagement in the official framework.",
      inputSchema: {
        category: z.string().optional().describe("Optional WSTG category id (e.g. WSTG-INPV) or name (e.g. 'Input Validation')."),
      },
    },
    async ({ category }) => {
      return { content: [{ type: "text", text: JSON.stringify(_wstgMap(category)) }] };
    },
  );

  server.registerTool(
    "technique_lookup",
    {
      title: "Detailed bug-hunting technique base",
      description:
        "INTEL: return the DETAILED methodology + tricks for one vulnerability class (52 classes: ssrf, request smuggling, cache poisoning, race conditions, ssti, deserialization, prototype pollution, mass assignment, sql/nosql injection, xss, cors, csrf, jwt, oauth, host header, open redirect, subdomain takeover, idor, graphql, websocket, file upload, path traversal/LFI, command injection, xxe, crlf, ldap, xpath, xslt, ssi, xssi, email, formula/CSV, orm, rsql, unicode, dangling markup, account takeover, 2fa bypass, rate-limit, password reset, captcha, registration, payment bypass, timing, uuid, reverse tabnabbing, iframe traps, cookies, postMessage, ...). Each returns summary, objectives, how_to_test steps, concrete techniques, and verify (marker + negative control). Load before testing a class to hunt it in detail.",
      inputSchema: {
        cls: z.string().optional().describe("Optional class id or name (e.g. 'ssrf', 'request smuggling', 'ssti')."),
      },
    },
    async ({ cls }) => {
      return { content: [{ type: "text", text: JSON.stringify(_techniqueLookup(cls)) }] };
    },
  );

  server.registerTool(
    "framework_tricks",
    {
      title: "Framework-specific exploitation tricks",
      description:
        "INTEL: return framework-specific exploitation knowledge for a framework (Laravel, Django, Flask, Node/Express, Next.js, Vue, Angular, WordPress, Joomla, Spring, JSP, Python, Go, Ruby/Rails, Perl, GraphQL) — detection signals, known vulns/CVEs, and concrete attack tricks. Use after detect_framework to hunt that framework's specific weaknesses.",
      inputSchema: {
        framework: z.string().optional().describe("Optional framework name (e.g. 'laravel', 'django', 'wordpress')."),
      },
    },
    async ({ framework }) => {
      return { content: [{ type: "text", text: JSON.stringify(_frameworkTricks(framework)) }] };
    },
  );

  server.registerTool(
    "resource_lookup",
    {
      title: "Curated security resource index (all domains)",
      description:
        "INTEL: return the FULL curated security resource index (78 entries, 44 domains — every entry from the community Awesome-Hacking meta-list: web, api, pentest, recon, payload, cve, privesc, source, fuzzing, llm, framework, osint, rev, cracking, forensics, malware, ir, intel, cicd, devsecops, defense, knowledge, labs, ctf, mobile, iot, ics, vehicle, drone, cellular, rtc, mainframe, rf, physical, social, web3, ...). Each has name, URL, description, and use_when. Search by category or keyword to find the best domain-specific tools/knowledge for ANY target.",
      inputSchema: {
        category: z.string().optional().describe("Optional category id or keyword (e.g. 'web', 'payload', 'recon', 'privesc')."),
      },
    },
    async ({ category }) => {
      return { content: [{ type: "text", text: JSON.stringify(_resourceLookup(category)) }] };
    },
  );

  server.registerTool(
    "taxonomy",
    {
      title: "OWASP Top 10 / API Top 10 / CWE / ASVS taxonomy",
      description:
        "INTEL: return standard taxonomy for grounding + professional reporting. taxonomy(web) = OWASP Top 10 (2021); taxonomy(api) = OWASP API Security Top 10 (2023); taxonomy(cwe, query) = CWE ID for a technique class; taxonomy(asvs) = ASVS verification chapters. Each maps to Blitz Strike coverage. Use to map findings to standard IDs (A01, API1, CWE-79, V4, ...).",
      inputSchema: {
        kind: z.string().optional().describe("'web' (OWASP Top 10), 'api' (API Top 10), 'cwe' (CWE mapping), or 'asvs' (ASVS chapters)."),
        query: z.string().optional().describe("Optional query: a technique class id (for cwe) or a risk/chapter id (for web/api/asvs)."),
      },
    },
    async ({ kind, query }) => {
      return { content: [{ type: "text", text: JSON.stringify(_taxonomy(kind, query)) }] };
    },
  );

  server.registerTool(
    "engagement_start",
    {
      title: "Start an engagement",
      description:
        "ORCHESTRATION: open an engagement and track its state. Call at the start of a full audit so subsequent engagement_phase / engagement_track / engagement_status calls have a state to update. The LLM is the brain; this is the deterministic bookkeeping hand.",
      inputSchema: {
        target: z.string().describe("The target (source path or live URL)."),
        kind: z.enum(["source", "live"]).optional().describe("source path or live URL. Defaults to source."),
      },
    },
    async ({ target, kind }) => {
      return { content: [{ type: "text", text: JSON.stringify(_startEngagement(target, kind)) }] };
    },
  );

  server.registerTool(
    "engagement_phase",
    {
      title: "Advance the engagement phase",
      description:
        "ORCHESTRATION: move the engagement to the next lifecycle phase (scope, recon, analyze, deep, verify, report). The phase tracks where the audit is; engagement_status uses it for the termination check.",
      inputSchema: {
        phase: z.string().describe("One of: scope, recon, analyze, deep, verify, report."),
      },
    },
    async ({ phase }) => {
      return { content: [{ type: "text", text: JSON.stringify(_setPhase(phase)) }] };
    },
  );

  server.registerTool(
    "engagement_track",
    {
      title: "Track a hypothesis",
      description:
        "ORCHESTRATION: record a hypothesis (a candidate finding keyed by its sink) with its status — pending, confirmed, or rejected. engagement_status derives the termination check from these; an untracked hypothesis is one the LLM has to remember, which is exactly what this avoids.",
      inputSchema: {
        sink: z.string().describe("The sink / candidate identifier (e.g. 'POST /upload -> eval()')."),
        status: z.enum(["pending", "confirmed", "rejected"]).optional().describe("Defaults to pending."),
      },
    },
    async ({ sink, status }) => {
      return { content: [{ type: "text", text: JSON.stringify(_trackHypothesis(sink, status)) }] };
    },
  );

  server.registerTool(
    "engagement_status",
    {
      title: "Engagement status + termination check",
      description:
        "ORCHESTRATION: return the current engagement state — phase, hypotheses, counts — and a deterministic termination check (done or the exact unmet criteria). Call this instead of asking yourself 'am I done?'. Also drives blitz_status-style progress.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_engagementStatus()) }] };
    },
  );

  server.registerTool(
    "read_payload",
    {
      title: "Read a payload collection",
      description: "INTEL: read the full payload collection for a category (or a specific file).",
      inputSchema: {
        category: z.string().describe("Payload category name"),
        file: z.string().optional().describe("Specific file within the category (optional)"),
      },
    },
    async ({ category, file }) => {
      return { content: [{ type: "text", text: JSON.stringify(_readPayload(category, file)) }] };
    },
  );

  server.registerTool(
    "template_lookup",
    {
      title: "Look up nuclei detection templates",
      description: "INTEL: find nuclei YAML templates matching a CVE/tech/topic (11.9k templates).",
      inputSchema: {
        topic: z.string().describe("CVE id, tech, or keyword (e.g. 'CVE-2021-44228', 'wordpress')"),
        limit: z.number().int().optional().describe("Max templates to return (default 10)"),
      },
    },
    async ({ topic, limit }) => {
      return { content: [{ type: "text", text: JSON.stringify(_templateLookup(topic, limit ?? 10)) }] };
    },
  );

  // -------------------------------------------------------------------------
  // FINDINGS + EVIDENCE (evidence-first finding engine)
  // -------------------------------------------------------------------------

  server.registerTool(
    "finding_create",
    {
      title: "Create a canonical finding",
      description:
        "FINDINGS: create a canonical, evidence-first finding. Severity describes impact; confidence (deterministic) describes certainty. Default status=detected (hypothesis-pending).",
      inputSchema: {
        title: z.string().describe("Finding title"),
        target_type: z.string().optional().describe("Target type (web/api/source/mobile/network/other)"),
        host: z.string().optional().describe("Target host"),
        endpoint: z.string().optional().describe("Target endpoint/path"),
        severity: z.string().describe("Severity: critical/high/medium/low/informational"),
        cwe: z.string().optional().describe("CWE id (e.g. CWE-89)"),
        source_type: z.string().describe("Source type (e.g. request_parameter, post_body, header, cookie, file)"),
        source_name: z.string().describe("Source name"),
        sink_type: z.string().describe("Sink type (e.g. sql_execution, command_execution, file_operations)"),
        sink_symbol: z.string().optional().describe("Sink symbol (e.g. '->query(')"),
        chain_id: z.string().optional().describe("Escalation chain id"),
      },
    },
    async ({ title, target_type, host, endpoint, severity, cwe, source_type, source_name, sink_type, sink_symbol, chain_id }) => {
      const f = makeFinding({
        title,
        target: { type: (target_type as FindingTarget["type"]) ?? "web", host, endpoint },
        severity: (severity as Severity) ?? "medium",
        cwe,
        source: { type: source_type, name: source_name },
        sink: { type: sink_type, symbol: sink_symbol },
        chainId: chain_id ?? null,
        status: "detected",
      });
      return { content: [{ type: "text", text: JSON.stringify(f) }] };
    },
  );

  server.registerTool(
    "finding_transition",
    {
      title: "Advance a finding lifecycle",
      description:
        "FINDINGS: advance a finding through its strict lifecycle (detected->triaged->hypothesis->validating->confirmed). Rejects illegal transitions.",
      inputSchema: {
        status: z.string().describe("Current status"),
        to: z.string().describe("Target status (triaged/hypothesis/validating/confirmed/false_positive/rejected/blocked/out_of_scope)"),
      },
    },
    async ({ status, to }) => {
      const ok = _canTransition(status as FindingStatus, to as FindingStatus);
      return { content: [{ type: "text", text: JSON.stringify({ from: status, to, legal: ok }) }] };
    },
  );

  server.registerTool(
    "confidence_score",
    {
      title: "Compute deterministic confidence",
      description:
        "FINDINGS: compute a deterministic weighted confidence score (static/data-flow/reachability/preconditions/validation/negative-control). Never an AI opinion.",
      inputSchema: {
        static_analysis: z.boolean().optional(),
        data_flow: z.boolean().optional(),
        reachability: z.boolean().optional(),
        preconditions: z.boolean().optional(),
        runtime_validation: z.boolean().optional(),
        negative_control: z.boolean().optional(),
      },
    },
    async (factors) => {
      const score = _computeConfidence(factors);
      return { content: [{ type: "text", text: JSON.stringify({ score, level: _confidenceLevel(score) }) }] };
    },
  );

  server.registerTool(
    "confidence_weights",
    {
      title: "Get/set confidence weights",
      description:
        "FINDINGS: inspect or override the deterministic confidence weights (configurable per the framework spec). Pass `set` (JSON object of weight overrides) to change them; omit to read the current weights.",
      inputSchema: {
        set: z.string().optional().describe("JSON object of weight overrides (e.g. {\"data_flow\":0.3})"),
      },
    },
    async ({ set }) => {
      if (set) {
        let w: Record<string, number>;
        try { w = JSON.parse(set); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid JSON" }) }] }; }
        _setConfidenceWeights(w);
      }
      return { content: [{ type: "text", text: JSON.stringify({ weights: _getConfidenceWeights() }) }] };
    },
  );

  server.registerTool(
    "finding_attach_evidence",
    {
      title: "Attach evidence to a finding",
      description:
        "FINDINGS: attach a redacted, SHA-256-tagged evidence record to an existing canonical finding (without advancing its lifecycle).",
      inputSchema: {
        finding: z.string().describe("JSON of the Finding object"),
        type: z.string().describe("Evidence type (source_location/response/validation_result/negative_control/...)"),
        description: z.string().describe("Evidence description"),
        content: z.string().optional().describe("Evidence artifact content"),
      },
    },
    async ({ finding, type, description, content }) => {
      let f: Finding;
      try { f = JSON.parse(finding); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid finding JSON" }) }] }; }
      const ev = _makeEvidence({ type: type as EvidenceType, description, artifacts: content ? [{ name: "artifact", kind: "evidence", content }] : [] });
      const updated = _attachEvidence(f, ev);
      return { content: [{ type: "text", text: JSON.stringify(updated) }] };
    },
  );

  server.registerTool(
    "redact",
    {
      title: "Redact secrets from text",
      description:
        "EVIDENCE: redact passwords/API keys/tokens/cookies/private keys from text before persisting evidence or reporting.",
      inputSchema: { text: z.string().describe("Text to redact") },
    },
    async ({ text }) => {
      return { content: [{ type: "text", text: JSON.stringify({ redacted: _redactSecrets(text) }) }] };
    },
  );

  // -------------------------------------------------------------------------
  // EAGLE-EYE DATA-FLOW (§7-11)
  // -------------------------------------------------------------------------

  server.registerTool(
    "trace_data_flow",
    {
      title: "Trace source-to-sink data flow",
      description:
        "EAGLE-EYE: trace data flow in a file — classify sources, sinks, sanitizers, and authorization gates. Returns candidates (reachable+unsanitized), sanitized (not findings), and authorized (lower priority).",
      inputSchema: { path: z.string().describe("Source file path") },
    },
    async ({ path }) => {
      const r = traceDataFlow(path);
      const taintedSinks = [...new Set(r.candidates.map((c) => c.sink?.id ?? "unknown"))];
      const guidance = nextSteps({
        tier: "eagle-eye",
        hasFindings: r.candidates.length > 0,
        sanitizedCount: r.sanitized.length,
        taintedSinks,
      });
      return { content: [{ type: "text", text: JSON.stringify({ ...r, next_steps: guidance }) }] };
    },
  );

  server.registerTool(
    "variant_analysis",
    {
      title: "Group findings by root cause",
      description:
        "EAGLE-EYE: variant analysis — group data-flow candidates by root cause (sink category + source), deduplicating identical patterns across files.",
      inputSchema: { path: z.string().describe("Source directory path") },
    },
    async ({ path }) => {
      const { iterSourceFiles } = await import("./scanner.js");
      const files = iterSourceFiles(path, 5000);
      const results = files.map((f) => traceDataFlow(f));
      const groups = groupVariants(results);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            files_analyzed: files.length,
            total_candidates: results.reduce((n, r) => n + r.candidates.length, 0),
            variant_groups: groups.length,
            groups,
          }),
        }],
      };
    },
  );

  // -------------------------------------------------------------------------
  // TAINT (§7 inter-procedural)
  // -------------------------------------------------------------------------

  server.registerTool(
    "taint_scan",
    {
      title: "Inter-procedural taint analysis",
      description:
        "EAGLE-EYE: real taint tracking — variable assignment, cross-function flow, and sanitizer awareness. Finds tainted data reaching sinks even across function boundaries.",
      inputSchema: { path: z.string().describe("Source file path") },
    },
    async ({ path }) => {
      const r = analyzeTaint(path);
      const taintedSinks = [...new Set(r.findings.map((f) => f.sink))];
      const guidance = nextSteps({
        tier: "eagle-eye",
        hasFindings: r.findings.length > 0,
        sanitizedCount: r.suppressed,
        taintedSinks,
      });
      return { content: [{ type: "text", text: JSON.stringify({ ...r, next_steps: guidance }) }] };
    },
  );

  server.registerTool(
    "eagle_eye2",
    {
      title: "Whole-program interprocedural taint (EAGLE-EYE 2.0)",
      description:
        "EAGLE-EYE 2.0: whole-program data-flow on a PHP AST — call-graph-aware interprocedural taint with return propagation, by-reference alias tracking, ternary/conditional merge, context-sensitive sanitizers, and authorization-gate detection. Prefer this over taint_scan for accurate cross-function reachability.",
      inputSchema: { path: z.string().describe("Source file path (PHP)") },
    },
    async ({ path }) => {
      const r = analyzeDataFlow2(path);
      const taintedSinks = [...new Set(r.findings.map((f) => f.sink))];
      const authGated = r.findings.filter((f) => f.auth_gated).length;
      const guidance = nextSteps({
        tier: "eagle-eye",
        hasFindings: r.findings.length > 0,
        sanitizedCount: r.suppressed,
        taintedSinks,
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            file: r.file,
            findings: r.findings.length,
            suppressed: r.suppressed,
            auth_gated: authGated,
            interprocedural: r.findings.filter((f) => f.interprocedural).length,
            functions: r.summary.functions,
            methods: r.summary.methods,
            call_edges: r.summary.edges,
            entry_points: r.summary.entry_points,
            unreachable: r.summary.unreachable,
            results: r.findings,
            next_steps: guidance,
          }),
        }],
      };
    },
  );

  server.registerTool(
    "route_scan",
    {
      title: "Route-confusion & dispatch-abuse scan",
      description:
        "Route confusion (separate class from source→sink taint): detect attacker-controlled dispatch (call_user_func/forward/dispatch), dynamic method calls ($obj->$m()), dynamic include (LFI), batch/proxy forwarding without per-route auth re-check, and route matching without path normalization.",
      inputSchema: { path: z.string().describe("Source file path (PHP)") },
    },
    async ({ path }) => {
      const code = readFileSync(path, "utf8");
      const findings = detectRouteConfusion(code, path);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ file: path, findings }),
        }],
      };
    },
  );

  server.registerTool(
    "complex_scan",
    {
      title: "Complex-bug scan (deserialization / type juggling / mass assignment / prototype pollution / CRLF / path confusion)",
      description:
        "Complex-bug detection beyond taint: deserialization→POP gadget chain (unserialize + magic method), type juggling (loose ==/!= vs hash/secret), mass assignment (extract/parse_str without a safe flag), prototype pollution (unsafe merge of request data), CRLF/header injection (user input into a header), and path confusion (user input into a file path without canonicalization).",
      inputSchema: { path: z.string().describe("Source file path") },
    },
    async ({ path }) => {
      const code = readFileSync(path, "utf8");
      const findings = detectComplexBugs(code, path);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ file: path, findings }),
        }],
      };
    },
  );

  server.registerTool(
    "diff_analyze",
    {
      title: "Differential security analysis",
      description:
        "PHASE 4: compare two versions of code (files or a git commit range) and surface only security-sensitive changes — new vulnerabilities, fixed vulnerabilities, new sinks/sources, removed sanitizers, and removed authorization gates.",
      inputSchema: {
        old_path: z.string().optional().describe("Old file path"),
        new_path: z.string().optional().describe("New file path"),
        old_code: z.string().optional().describe("Old source code (when not using paths)"),
        new_code: z.string().optional().describe("New source code (when not using paths)"),
        language: z.string().optional().describe("Language (php/javascript/python/java); auto-detected from path if omitted"),
        repo: z.string().optional().describe("Git repo path (for git-diff mode)"),
        base: z.string().optional().describe("Git base ref (default HEAD~1)"),
        head: z.string().optional().describe("Git head ref (default HEAD)"),
      },
    },
    async ({ old_path, new_path, old_code, new_code, language, repo, base, head }) => {
      if (repo) {
        const r = analyzeGitDiff(repo, base ?? "HEAD~1", head ?? "HEAD");
        return { content: [{ type: "text", text: JSON.stringify(r) }] };
      }
      let result;
      if (old_path && new_path) {
        result = analyzeDifferentialFiles(old_path, new_path, language);
      } else if (old_code !== undefined && new_code !== undefined) {
        result = analyzeDifferential(old_code, new_code, language ?? "php", new_path ?? "target");
      } else {
        return { content: [{ type: "text", text: JSON.stringify({ error: "provide (old_path+new_path), (old_code+new_code), or (repo)" }) }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    },
  );

  server.registerTool(
    "incremental_scan",
    {
      title: "Incremental scan (CI)",
      description:
        "EAGLE-EYE: analyze only the files changed between two git refs (default HEAD~1..HEAD) — the fast CI pass. Runs the taint + data-flow engine on just the changed source files and skips unchanged ones; the full-scan path (run_engagement / enrich_scan) remains authoritative.",
      inputSchema: {
        repo: z.string().describe("Path to the git repo."),
        base: z.string().optional().describe("Base ref (default HEAD~1)."),
        head: z.string().optional().describe("Head ref (default HEAD)."),
      },
    },
    async ({ repo, base, head }) => {
      return { content: [{ type: "text", text: JSON.stringify(_analyzeChangedFiles(repo, base ?? "HEAD~1", head ?? "HEAD")) }] };
    },
  );

  server.registerTool(
    "list_frameworks",
    {
      title: "List supported frameworks",
      description:
        "PHASE 5: list the web frameworks Blitz Strike understands for framework-aware security analysis (Laravel, WordPress, Express, Next.js, Django, FastAPI, Spring).",
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify({ frameworks: listFrameworks() }) }] };
    },
  );

  server.registerTool(
    "detect_framework",
    {
      title: "Detect web framework",
      description:
        "PHASE 5: detect the web framework used by a source file (reads the file, then scores each framework's detection signals for the file's language).",
      inputSchema: {
        path: z.string().optional().describe("Source file path (alternative: code)"),
        code: z.string().optional().describe("Source code directly (alternative to path)"),
        language: z.string().optional().describe("Language (auto-detected from path if omitted)"),
      },
    },
    async ({ path, code, language }) => {
      let src = code ?? "";
      let lang = language;
      if (path && !code) {
        try {
          src = readFileSync(path, "utf8");
        } catch {
          return { content: [{ type: "text", text: JSON.stringify({ error: `cannot read ${path}` }) }] };
        }
        lang = lang ?? detectLanguage(path)?.language ?? "php";
      }
      const d = detectFramework(src, lang ?? "php");
      const scan = d.framework ? scanFramework(src, d.framework) : null;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            framework: d.framework,
            language: d.language,
            candidates: d.candidates,
            scan,
          }),
        }],
      };
    },
  );

  server.registerTool(
    "framework_intel",
    {
      title: "Framework security knowledge",
      description:
        "PHASE 5: return a framework's security knowledge (sources, sinks, sanitizers, auth gates, routing, ORM, middleware) and optionally scan code with those patterns.",
      inputSchema: {
        framework: z.string().describe("Framework id (see list_frameworks)"),
        code: z.string().optional().describe("Optional source code to scan with the framework's patterns"),
      },
    },
    async ({ framework, code }) => {
      const profile = frameworkProfile(framework);
      if (!profile) {
        return { content: [{ type: "text", text: JSON.stringify({ error: `unknown framework: ${framework}` }) }] };
      }
      const out: Record<string, unknown> = { profile };
      if (code !== undefined) out.scan = scanFramework(code, framework);
      return { content: [{ type: "text", text: JSON.stringify(out) }] };
    },
  );

  server.registerTool(
    "browser_validate",
    {
      title: "Browser validation (Playwright)",
      description:
        "PHASE 6: validate a static-analysis HYPOTHESIS by driving a real headless Chromium. Checks: dom_xss, open_redirect, auth_bypass, csrf. Use only when necessary — to confirm a hypothesis with browser evidence, not as a first-pass scan. Requires playwright-core (optional peer dependency).",
      inputSchema: {
        check: z.enum(["dom_xss", "open_redirect", "auth_bypass", "csrf"]).describe("Validation check to run"),
        target: z.string().describe("Target URL (use {{payload}} placeholder for dom_xss/open_redirect injection)"),
        payload: z.string().optional().describe("Payload to inject (defaults to an XSS marker for dom_xss)"),
      },
    },
    async ({ check, target, payload }) => {
      const result = await browserValidate(check as BrowserCheck, target, payload);
      return { content: [{ type: "text", text: JSON.stringify(result) }] };
    },
  );

  server.registerTool(
    "browser_agent",
    {
      title: "Browser automation agent (session)",
      description:
        "PHASE 12: drive a real headless-Chromium session. Ops: open, navigate, click, type, evaluate, screenshot, back, forward, get_cookie, set_cookie, plus detect_auth_form, diagnostics, close. Enables multi-step flows (login/MFA) and DOM issue detection. Requires playwright-core (optional peer dependency).",
      inputSchema: {
        op: z.enum(["open", "navigate", "click", "type", "evaluate", "screenshot", "back", "forward", "get_cookie", "set_cookie", "detect_auth_form", "diagnostics", "close"]),
        args: z.array(z.string()).optional().describe("Positional args (url, selector, text, js, cookie name/value, screenshot path)"),
      },
    },
    async ({ op, args }) => {
      if (op === "detect_auth_form") {
        const r = await detectAuthForm();
        return { content: [{ type: "text", text: JSON.stringify(r) }] };
      }
      if (op === "diagnostics") {
        return { content: [{ type: "text", text: JSON.stringify(browserDiagnostics()) }] };
      }
      if (op === "close") {
        await browserClose();
        return { content: [{ type: "text", text: JSON.stringify({ ok: true, detail: "session closed" }) }] };
      }
      const r = await browserAgent(op as BrowserOp, args ?? []);
      return { content: [{ type: "text", text: JSON.stringify(r) }] };
    },
  );

  server.registerTool(
    "taint_tree",
    {
      title: "Whole-tree taint scan",
      description:
        "EAGLE-EYE: run inter-procedural taint analysis across an entire source tree.",
      inputSchema: {
        path: z.string().describe("Source directory path"),
        max_files: z.number().int().optional().describe("Max files (default 2000)"),
      },
    },
    async ({ path, max_files }) => {
      const results = taintTree(path, max_files ?? 2000);
      const totalFindings = results.reduce((n, r) => n + r.findings.length, 0);
      const totalSuppressed = results.reduce((n, r) => n + r.suppressed, 0);
      const taintedSinks = [...new Set(results.flatMap((r) => r.findings.map((f) => f.sink)))];
      const guidance = nextSteps({
        tier: "eagle-eye",
        hasFindings: totalFindings > 0,
        sanitizedCount: totalSuppressed,
        taintedSinks,
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            files_analyzed: results.length,
            total_findings: totalFindings,
            total_suppressed: totalSuppressed,
            findings: results.filter((r) => r.findings.length > 0).map((r) => ({ file: r.file, findings: r.findings })),
            next_steps: guidance,
          }),
        }],
      };
    },
  );

  // -------------------------------------------------------------------------
  // UNIVERSAL TAINT (multi-language)
  // -------------------------------------------------------------------------

  server.registerTool(
    "list_languages",
    {
      title: "List supported taint languages",
      description:
        "EAGLE-EYE: list languages supported by the universal taint engine. " +
        "USE WHEN: you need to know whether taint_file can analyze a given source file, or before choosing taint_scan (PHP AST) vs taint_file (multi-language).",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify({ languages: listLanguages() }) }] };
    },
  );

  server.registerTool(
    "taint_file",
    {
      title: "Universal multi-language taint scan",
      description:
        "EAGLE-EYE: language-agnostic taint analysis. Auto-detects PHP/JS/TS/Python/Java by extension and tracks attacker-controlled input to dangerous sinks, with sanitizer awareness. " +
        "USE WHEN: you have a source file and need to know whether a dangerous sink (SQL/command/code-exec/file/redirect/XSS) is actually REACHABLE by user input. " +
        "NEXT: if a tainted sink is found, it is a HYPOTHESIS — validate it live with strike_verify (marker + negative control) before reporting; or record it with finding_create.",
      inputSchema: {
        path: z.string().describe("Source file path (extension determines language)"),
        code: z.string().optional().describe("Raw source code (overrides file read)"),
      },
    },
    async ({ path, code }) => {
      const lang = detectLanguage(path);
      if (!lang) {
        return { content: [{ type: "text", text: JSON.stringify({ file: path, language: "unknown", error: "no adapter for this extension; supported: " + listLanguages().map((l) => l.extensions.join("/")).join(", ") }) }] };
      }
      let src = code;
      if (!src) {
        const { readFileSync } = await import("node:fs");
        try { src = readFileSync(path, "utf8"); } catch { return { content: [{ type: "text", text: JSON.stringify({ file: path, error: "unreadable" }) }] }; }
      }
      const r = analyzeTaintUniversal(src, path);
      const taintedSinks = [...new Set(r.findings.map((f) => f.sink))];
      const guidance = nextSteps({
        tier: "eagle-eye",
        hasFindings: r.findings.length > 0,
        sanitizedCount: r.suppressed,
        taintedSinks,
      });
      return { content: [{ type: "text", text: JSON.stringify({ ...r, next_steps: guidance }) }] };
    },
  );

  // -------------------------------------------------------------------------
  // PHASE 4: CVSS + DEDUP + REPORT
  // -------------------------------------------------------------------------

  server.registerTool(
    "cvss_score",
    {
      title: "Compute CVSS v3.1 base score",
      description:
        "CVSS: compute a deterministic CVSS v3.1 base score + vector + severity from metric values (AV/AC/PR/UI/S/C/I/A). Self-computed, not read from NVD.",
      inputSchema: {
        AV: z.string().optional().describe("Attack Vector: N/A/L/P"),
        AC: z.string().optional().describe("Attack Complexity: L/H"),
        PR: z.string().optional().describe("Privileges Required: N/L/H"),
        UI: z.string().optional().describe("User Interaction: N/R"),
        S: z.string().optional().describe("Scope: U/C"),
        C: z.string().optional().describe("Confidentiality: H/L/N"),
        I: z.string().optional().describe("Integrity: H/L/N"),
        A: z.string().optional().describe("Availability: H/L/N"),
      },
    },
    async (input) => {
      return { content: [{ type: "text", text: JSON.stringify(cvssAssess(input as CvssInput)) }] };
    },
  );

  server.registerTool(
    "dedup_findings",
    {
      title: "Deduplicate findings by root cause",
      description:
        "FINDINGS: collapse a list of findings that share a root cause (sink type + source type + CWE) into one group per root cause.",
      inputSchema: {
        findings: z.string().describe("JSON array of Finding objects"),
      },
    },
    async ({ findings }) => {
      let list: Finding[];
      try { list = JSON.parse(findings); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid JSON" }) }] }; }
      const groups = dedupFindings(list);
      const unique = uniqueFindings(list);
      return { content: [{ type: "text", text: JSON.stringify({ groups: groups.map((g) => ({ signature: g.signature, count: g.count, representative: g.representative.id })), unique_findings: unique.map((f) => f.id) }) }] };
    },
  );

  server.registerTool(
    "generate_report",
    {
      title: "Generate a reproducible report",
      description:
        "REPORT: emit a deterministic markdown (or JSON) report from canonical Findings, with summary + integrity hash. Reproducible: same findings -> byte-identical output.",
      inputSchema: {
        findings: z.string().describe("JSON array of Finding objects"),
        format: z.enum(["markdown", "json"]).optional().describe("Report format"),
        title: z.string().optional().describe("Report title"),
        scope: z.string().optional().describe("Scope description"),
      },
    },
    async ({ findings, format, title, scope }) => {
      let list: Finding[];
      try { list = JSON.parse(findings); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid JSON" }) }] }; }
      const opts = { title, scope, version: VERSION };
      const out = (format ?? "markdown") === "json" ? reportJson(list, opts) : reportMarkdown(list, opts);
      return { content: [{ type: "text", text: out }] };
    },
  );

  server.registerTool(
    "run_benchmark",
    {
      title: "Run the benchmark suite",
      description:
        "BENCHMARK: run the labelled corpus and report detection rate, false-positive rate, and precision. The quality metric, not the tool count.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(runBenchmark()) }] };
    },
  );

  server.registerTool(
    "coverage_matrix",
    {
      title: "Report coverage matrix",
      description:
        "BENCHMARK: enumerate language × sink-class coverage (which languages detect which sink types), plus the coverage ratio.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(coverageMatrix()) }] };
    },
  );

  server.registerTool(
    "run_enterprise_benchmark",
    {
      title: "Run the enterprise (framework-style) benchmark",
      description:
        "BENCHMARK: run the deterministic detectors (taint + route-confusion + complex-bugs) against realistic framework fixtures (Laravel/Express/Django/Spring + batch-route + complex-bugs) and report per-fixture recall.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(runEnterpriseBenchmark()) }] };
    },
  );

  server.registerTool(
    "check_update",
    {
      title: "Check for a newer blitzstrike version",
      description:
        "UPDATE: query the npm registry for the latest blitzstrike version. Tells a driving agent whether the package or the data cache is stale.",
      inputSchema: {},
    },
    async () => {
      const latest = await checkLatestVersion();
      return { content: [{ type: "text", text: JSON.stringify({ latest, note: "package updates via `npx blitzstrike` (always-latest) or `npm i -g blitzstrike@latest`; heavy data via `blitzstrike sync-data`" }) }] };
    },
  );

  return server;
}

export async function serve(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
