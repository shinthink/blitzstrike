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
  runAutonomous,
  listChains,
  formatStatus,
  formatPlanChecklist,
  classifyTarget,
} from "./orchestrator.js";
import { buildPlan, computeGuidance } from "./orchestration.js";
import { decomposeBatches, retryPattern, worktree, watchdog, compactState } from "./ops.js";
import { taskStart, taskCheckpoint, taskStatus, taskResume } from "./tasks.js";
import {
  toolLookup,
  listTools,
  skillLookup,
  listSkills,
  readSkill,
  ensureTool,
  toolForHint,
  runCatalogTool,
  installAllTools,
} from "./catalog.js";
import { researchHeaders } from "./http.js";
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
  attackPlan as _attackPlan,
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
import { makeFinding, transition as _transition, canTransition as _canTransition, LIFECYCLE_TRANSITIONS as _LIFECYCLE, computeConfidence as _computeConfidence, confidenceLevel as _confidenceLevel, setConfidenceWeights as _setConfidenceWeights, getConfidenceWeights as _getConfidenceWeights, attachEvidence as _attachEvidence, type FindingStatus, type FindingTarget, type Severity, type Finding } from "./finding.js";
import { makeEvidence as _makeEvidence, redactSecrets as _redactSecrets, type EvidenceType } from "./evidence.js";
import { traceDataFlow, groupVariants } from "./dataflow.js";
import { analyzeTaint, taintTree } from "./taint.js";
import { analyzeDataFlow2 } from "./eagle2.js";
import { analyzeDifferential, analyzeDifferentialFiles, analyzeGitDiff } from "./differential.js";
import { listFrameworks, detectFramework, frameworkProfile, scanFramework } from "./frameworks.js";
import { browserValidate, type BrowserCheck } from "./browser.js";
import { browserAgent, detectAuthForm, browserDiagnostics, browserClose, type BrowserOp } from "./browser-agent.js";
import { driveChromeDevtools } from "./devtools.js";
import { checkMcpServers } from "./mcp-status.js";
import { analyzeTaintUniversal, detectLanguage, listLanguages } from "./universal-taint.js";
import { detectRouteConfusion } from "./route-confusion.js";
import { detectComplexBugs } from "./complex-bugs.js";
import "./adapters.js"; // register language adapters at import time
import { nextSteps } from "./guidance.js";
import { scanSinks, detectSourceLeak } from "./sinks.js";
import { crackHash } from "./hash.js";
import { liveRecon } from "./live-recon.js";
import { strikeVerify, verifyFileRead, resolveFinding as _resolveFinding, type StrikeVerdict } from "./strike.js";
import { cvssAssess, type CvssInput } from "./cvss.js";
import { dedupFindings, uniqueFindings } from "./dedup.js";
import { reportMarkdown, reportJson, saveReport } from "./report.js";
import { runBenchmark, captureFalsePositive } from "./benchmark.js";
import { recordVerdict, sinkToVector, hitRates, topVectors, queryIntel } from "./intelligence.js";
import { complianceMap, complianceSummary } from "./compliance.js";
import { createObligation, nextObligation as _nextObligation, dischargeObligation as _dischargeObligation, listObligations as _listObligations, openCount as _openCount } from "./obligations.js";
import { analyzeSecurityState } from "./security-state.js";
import { runEnterpriseBenchmark } from "./enterprise-benchmark.js";
import { coverageMatrix } from "./coverage.js";
import { checkLatestVersion } from "./update.js";
import { VERSION } from "./version.js";

export function createServer(): McpServer {
  const server = new McpServer(
    {
      name: "blitzstrike",
      version: VERSION,
    },
    {
      instructions:
        "Blitz Strike — deterministic security-audit toolbelt. You reason; its tools do the deterministic work (scan, taint, verify, evidence).\\n\\n" +
        "FIRST ACTION (when the user says test / scan / audit / engagement / pentest <URL or path>):\\n" +
        "- Call run_engagement(target) — or run_autonomous(target) to also get escalation paths. ONE call runs the whole engagement (recon -> sweep -> checks -> report).\\n" +
        "- NEVER do manual live_recon / blitz_scan first, and never fall back to manual probing. Manual tools are ONLY for follow-up AFTER run_engagement, or when the user names a specific sub-step.\\n\\n" +
        "RULES (never violate):\\n" +
        "- A hit is a HYPOTHESIS; live verification (marker + negative control) is the verdict. Never report unverified.\n" +
        "- run_engagement / run_autonomous return status DETECTED (NOT \"complete\") — that is the signal to VERIFY. After detection you MUST strike_verify (or verify_file_read for CWE-22, drive_devtools for DOM/JS precision) on each finding, then generate_report. Detection without verification is NOT a deliverable.\n" +
        "- scope_check is intel-only, never gates. No scope = proceed (repo disclaimer carries responsibility). No authorization gate — hunt the target you are given.\\n" +
        "- strike_verify + live checks AUTO-attempt WAF bypass. Don't report 'needs bypass' without re-probing.\\n" +
        "- NEVER ask 'should I continue?' / 'say the word' / 'want me to pursue' / 'next?' — that is a hard violation. Execute the full chain autonomously until COMPLETE. COMPLETE means every lead verified/blocked AND every reachable chain step executed or blocked (no deferred escalations). Pause only: destructive/DoS consent, external block (OTP/cred), or genuine COMPLETE.\\n" +
        "- One hard stop: malicious/third-party infra ('find the actor') -> static + takedown only.\\n" +
        "- FINDING LIFECYCLE (stateful — never loop stateless tools): advance findings via finding_create -> strike_verify -> strike_resolve. finding_transition now takes a FULL finding JSON + target status and RETURNS the updated finding (pass the object, never a status string); a bad move returns 'illegal transition' + the legal next states. confidence_score is DETERMINISTIC (same factors -> same score) — call it ONCE, never retry; it changes nothing. SELF-HARDENING: when a finding is verified false_positive, call capture_false_positive(code, language, detector, note) with the triggering code so the detector gets more precise every engagement. PROOF-OBLIGATION LOOP (the structure, not a prompt): every pending hypothesis is an OPEN obligation. Drive the engagement as a single-decision loop — next_obligation() -> run the ONE test it names -> discharge_obligation(id, status=verified|refuted|blocked). COMPLETE is gated on zero open obligations (obligations().complete); generate_report warns while any remain. You hold NO plan in your head — the ledger is the single source of truth for what work remains.\\n\\n" +
        "CHAIN DECISIONS (a confirmed finding is the START, not the end):\\n" +
        "- For each confirmed finding, enumerate follow-ups with list_chains + chain_links: ESCALATE (what it becomes), CHAIN (compose with other findings), BYPASS, PIVOT (new surface now reachable).\\n" +
        "- Ask the chain-aware question: 'I found X -> what can I NOW read / do / access?' e.g. SQLi -> query the DB for credentials AND for the Werkzeug console PIN / secrets / source; LFI -> read configs, keys, PIN inputs; cred dump -> crack offline -> authenticate -> privileged actions.\\n" +
        "- Every follow-up is a HYPOTHESIS — verify each before it enters the report. Don't stop at 'found SQLi'; follow where the chain leads.\\n" +
        "- EXECUTE follow-ups NOW, not as 'next phase': any leaked source/error -> scan_leaked_source(text) to enumerate sinks (eval/exec/SECRET_KEY/creds) then exploit each; dumped hashes -> crack_hash(hash) now; hidden-content IDOR -> test the direct route. A 'next chain' you write is a TODO — run it, never leave it as a recommendation.\\n\\n" +
        "- DOCTRINE — 'if you can continue, why not? if possible, why not try?': a chain step you CAN execute is one you MUST execute. A PREREQUISITE is a chain step, NOT a separate engagement — e.g. a CORS->session-theft chain needing 'a foothold on any subdomain (XSS / dangling-DNS takeover)' means CHECK for it NOW: resolve every allowlisted subdomain and test each for dangling delegation (NXDOMAIN, unclaimed S3/bucket, dangling SaaS CNAME) + probe for XSS — do NOT write 'dangling-DNS audit is the next engagement'. Declaring COMPLETE while a reachable chain step is deferred is a violation.\\n\\n" +
        "DELIVERABLE + PERSISTENCE (recon is INPUT, not output):\n" +
        "- The deliverable is a HackerOne-grade FINDING report via generate_report, NEVER a hand-written recon/surface map. Recon is input; confirmed findings are the output.\n" +
        "- After recon, VERIFY every lead before it enters the report: strike_verify (marker + negative control) for HTTP, browser_validate for DOM/JS. A lead is a HYPOTHESIS until verified.\n" +
        "- A hard block (Cloudflare/WAF/IP-block/captcha) is NOT the end: mark the finding blocked + note the required vantage (residential / authorized / correct-SNI / --resolve direct-to-origin), then CONTINUE to the next lead (origin bypass, non-prod cluster, mobile APK, subdomain).\n" +
        "- Keep trying every lead AND every chain step until each is verified/executed or blocked, THEN generate_report. Never deliver a bare surface map, and never stop at 'found X' when X enables more.\n\n" +
        "TWO PATHS:\\n" +
        "- Source path on disk -> blitz_scan / taint_file / eagle_eye2 (static).\\n" +
        "- Live URL -> live_recon / active_scan / strike_verify (web-hunting).\\n\\n" +
        "DEEPEN A FINDING: attack_plan(target, tech, params) to get the prioritized vector plan (decide what to test next with data); list_chains (escalation), chain_links (compose), technique_lookup(cls), payload_lookup, bypass_lookup (blocked). Phase doctrine: read_skill(bs-orchestrate-engagement | bs-web-hunting | bs-source-audit | bs-verify-finding). Campaign plan: read_playbook(target-type). On any failure call retry_guidance(signal) / model_fallback(signal) before giving up.\n" +
        "KNOWLEDGE BASE (discover, don't guess): skillLookup(topic) / listSkills for the 40 attack-path + hunting skills (ap-*, hp-*, bs-*); list_attack_vectors / attack_vectors(cat) for the 34-category vector taxonomy; taxonomy(kind) for OWASP/CWE/ASVS/API-top-10; read_playbook(type) for the 17 campaign playbooks; list_manuals / read_tool_manual for 317 tool references; list_tools / run_catalog_tool for the 141-tool catalog. Every tool, skill, and data layer is reachable from these. CROSS-TARGET INTELLIGENCE: strike_resolve auto-records confirmed/false_positive verdicts into the empirical ledger; query it with intelligence(action=hit_rates/top_vectors) so a new target on a known tech inherits historical hit-rates (attack_plan already blends them into success_probability).\n" +
        "PRECISION ANALYSIS — chrome-devtools MCP is MANDATORY, not optional:\n" +
        "- When a lead needs DOM/JS precision — DOM-XSS sink execution, AJAX endpoint + payload interception, JS runtime errors, redirect chains, SSO/token flow, or anything a static HTML glance cannot prove — call drive_devtools(target). It spawns chrome-devtools-mcp and drives a REAL headless browser (navigate -> list_network_requests -> list_console_messages -> evaluate_script), giving reproducible evidence instead of a guess.\n" +
        "- Before calling it, check_mcp() to confirm the browser MCP is available; if not, blitzstrike install-tools or npm i -g chrome-devtools-mcp. Never substitute eyeballing minified JS or a static sink guess when a live browser can PROVE it. This is the precision + consistency layer.\n" +
        "EXTERNAL MCP SERVERS (verified, connect them — NOT one-shot CLIs): chrome-devtools-mcp (29 tools: list_network_requests/get_network_request for raw HTTP interception, list_console_messages for JS errors + DOM-XSS, evaluate_script to run JS, take_screenshot) -> stdio chrome-devtools-mcp --headless --chromeArg=--no-sandbox --chromeArg=--disable-gpu (as root/container this is MANDATORY or the browser crashes; add --proxyServer http://127.0.0.1:8080 to route through Burp, --acceptInsecureCerts for bad TLS). burp-suite-mcp (proxy history + active scan + repeater) -> NOT npm: build the JAR (git clone https://github.com/PortSwigger/mcp-server.git && cd mcp-server && ./gradlew embedProxyJar), load it in Burp Extensions, then connect the client to http://127.0.0.1:9876 (SSE) or the stdio proxy java -jar mcp-proxy-all.jar --sse-url http://127.0.0.1:9876.",
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
    "verify_file_read",
    {
      title: "Verify arbitrary file read / path traversal (marker file vs negative control)",
      description:
        "STRIKE: deterministic verification of an arbitrary-file-read / path-traversal hypothesis (CWE-22). Reads a marker file (/etc/passwd) vs a non-existent negative-control path and compares: confirmed (marker returns file content, control does not) / unconfirmed (indistinguishable or gated by auth) / blocked (unreachable). Supports raw POST body (bodyRaw=true) or a named query/body param. Never leaves a bare hypothesis — always returns a verdict + reason.",
      inputSchema: {
        url: z.string().describe("Target URL (e.g. the file-read endpoint)"),
        method: z.enum(["GET", "POST"]).optional().describe("HTTP method (default POST)"),
        param: z.string().optional().describe("Query/body param name that carries the path (default 'path')"),
        bodyRaw: z.boolean().optional().describe("Treat the raw POST body as the filesystem path (default false)"),
        headers: z.string().optional().describe("JSON object of extra headers"),
        markerPath: z.string().optional().describe("Marker file to read (default /etc/passwd)"),
        timeout: z.number().int().optional().describe("Timeout seconds (default 15)"),
      },
    },
    async ({ url, method, param, bodyRaw, headers, markerPath, timeout }) => {
      let hdrs: Record<string, string> = {};
      try { hdrs = headers ? JSON.parse(headers) : {}; } catch { /* ignore */ }
      const verdict = await verifyFileRead({
        url,
        method: method ?? "POST",
        param,
        bodyRaw: bodyRaw ?? false,
        headers: hdrs,
        markerPath,
        timeoutMs: timeout ? timeout * 1000 : undefined,
      });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...verdict,
            next_steps: [
              `Verdict: ${verdict.status} — ${verdict.reason}`,
              verdict.status === "confirmed"
                ? "Confirmed arbitrary file read. Record with finding_create + attach the marker/control evidence."
                : verdict.status === "blocked"
                  ? "Blocked. Target unreachable — retry or re-check scope."
                  : "Unconfirmed. The response is gated (auth/session) or the file is not read — obtain a low-priv session and re-run with a valid session, or mark the finding unconfirmed with this evidence.",
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
      // EMPIRICAL PRIOR: record the verified verdict into the intelligence ledger
      // so hit-rates feed back into attack_plan's success_probability (Bayesian).
      const outcome = v.status === "confirmed" ? "confirmed" : v.status === "false_positive" ? "false_positive" : null;
      if (outcome) {
        recordVerdict({
          vector: sinkToVector(f.sink?.type ?? ""),
          outcome,
          severity: f.classification?.severity,
          target: f.target?.host ?? f.target?.endpoint,
          cvss: f.classification?.cvss_score,
        });
      }
      return { content: [{ type: "text", text: JSON.stringify(updated) }] };
    },
  );

  server.registerTool(
    "scan_leaked_source",
    {
      title: "Scan leaked source/error text for sinks",
      description:
        "EAGLE-EYE: scan ARBITRARY leaked text (a 500 traceback, a debug page, a source dump, a config file, an error message, a credential dump) for dangerous sinks — eval/exec/os.system (RCE), render_template_string (SSTI), SQL string-building, requests.get (SSRF), file read (LFI), SECRET_KEY/API keys, hardcoded creds, pickle/unserialize, XML parse (XXE). Each hit returns the line, the snippet, and the next action. Use this the moment any response leaks code or config, so no sink is missed by eyeballing. Pass `text` directly, or `url` to fetch + scan a response.",
      inputSchema: {
        text: z.string().optional().describe("The leaked text to scan (source, traceback, config, error)"),
        url: z.string().optional().describe("A URL whose response should be fetched and scanned for source leaks + sinks"),
      },
    },
    async ({ text, url }) => {
      let body = text ?? "";
      if (url && !body) {
        try {
          const r = await fetch(url, { redirect: "follow", headers: researchHeaders() });
          body = await r.text();
        } catch {
          return { content: [{ type: "text", text: JSON.stringify({ error: "fetch failed", url }) }] };
        }
      }
      const leak = detectSourceLeak(body);
      const sinks = scanSinks(body);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            source_leak_detected: leak,
            sinks_found: sinks.length,
            sinks,
            hint: leak
              ? "This response leaks source/traceback. Enumerate each sink above and exploit it (RCE/secret first) — do not just note the leak."
              : "No classic traceback/debug signature detected; sinks below (if any) still apply to whatever text was scanned.",
          }),
        }],
      };
    },
  );

  server.registerTool(
    "crack_hash",
    {
      title: "Identify + crack a dumped credential hash",
      description:
        "CREDENTIAL: when you dump password hashes, EXECUTE this instead of leaving 'crack the hashes' as a recommendation. Identifies the hash type (bcrypt/md5/sha1/sha256/sha512/ntlm) and immediately tries a built-in common-password list offline, then returns the exact hashcat/john command for the full crack. Pass one hash string or a list.",
      inputSchema: {
        hash: z.string().describe("The hash string (or a list of hashes, one per line)"),
        extra: z.array(z.string()).optional().describe("Extra candidate passwords to try (e.g. usernames, target-specific words)"),
      },
    },
    async ({ hash, extra }) => {
      const hashes = hash.split(/\r?\n/).map((h) => h.trim()).filter(Boolean).slice(0, 50);
      const results = [];
      for (const h of hashes) {
        results.push({ hash: h.slice(0, 24) + (h.length > 24 ? "…" : ""), ...(await crackHash(h, extra ?? [])) });
      }
      return { content: [{ type: "text", text: JSON.stringify({ hashes_scanned: results.length, results }) }] };
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
        "STRIKE: the DEFAULT first call when the user asks to test / scan / audit / engagement / pentest a URL or source path. Runs the whole audit in ONE call (no babysitting): source path -> triage -> chain enrichment -> findings -> inline report (markdown+JSON+SARIF); URL -> full autonomous live pipeline (live_recon + reflected/headers/redirect/traversal/CORS + SSTI/SSRF/SQLi/command-injection/XSS) -> findings -> report.",
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
    "run_autonomous",
    {
      title: "STRIKE autonomous engagement (surface + escalation)",
      description:
        "ORCHESTRATION: like run_engagement but the escalation path is pre-attached to every finding (chain name/severity/prerequisites + ordered next_steps with action + tool_hint + success_criteria + negative_control). Use when the user asks to test / scan / audit a target and you want the 'what to do next' already computed per finding.",
      inputSchema: {
        target: z.string().describe("Source path or URL"),
        scope: z.string().optional().describe("Scope (for URL targets)"),
        mode: z.string().optional().describe("Engagement mode"),
        max_passes: z.number().int().min(1).max(5).optional().describe("Max deepen passes (default 3)"),
      },
    },
    async ({ target, scope, mode, max_passes }) => {
      const r = await runAutonomous(target, scope ?? "", mode ?? "bug-bounty", max_passes ?? 3);
      const banner = typeof r.banner === "string" ? r.banner : "";
      const statusLine = `→ ${Array.isArray(r.findings) ? r.findings.length : 0} finding(s), termination=${r.termination ?? "complete"}`;
      return {
        content: [
          { type: "text", text: banner ? `${banner}\n\n${statusLine}` : statusLine },
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

  server.registerTool(
    "run_catalog_tool",
    {
      title: "Run a catalog tool against a target",
      description:
        "CATALOG: map a tool name/hint to a catalog tool, ensure it is installed, and RUN it against a target (required flags auto-built; the first required string/path flag receives the target). Returns exit code + capped output. Use to execute a chain step's tool_hint (sqlmap/nuclei/jwt_tool/subfinder/...) instead of leaving it as 'manual'. Non-interactive — no destructive flags added beyond the tool's own required flags.",
      inputSchema: {
        hint: z.string().describe("Tool name or hint (e.g. sqlmap, nuclei, subfinder, jwt_tool)"),
        target: z.string().describe("Target URL/host to run it against"),
        extra_flags: z.array(z.string()).optional().describe("Extra CLI flags"),
      },
    },
    async ({ hint, target, extra_flags }) => {
      const name = toolForHint(hint);
      if (!name) return { content: [{ type: "text", text: JSON.stringify({ found: false, query: hint }) }] };
      return {
        content: [{ type: "text", text: JSON.stringify(runCatalogTool(hint, target, extra_flags ?? [])) }],
      };
    },
  );

  server.registerTool(
    "drive_devtools",
    {
      title: "Drive chrome-devtools-mcp against a target",
      description:
        "BROWSER: spawn chrome-devtools-mcp (a real headless Chrome) and drive it against a target URL — navigate, capture network requests/responses, console messages, and run a JS eval. Returns the live traffic + console + eval. This is the auto-verification of the 'browser_devtools' chain hint (raw HTTP interception the built-in browser cannot do).",
      inputSchema: {
        target: z.string().describe("Target URL to open in the browser"),
      },
    },
    async ({ target }) => {
      return { content: [{ type: "text", text: JSON.stringify(await driveChromeDevtools(target)) }] };
    },
  );

  server.registerTool(
    "check_mcp",
    {
      title: "Check external MCP integrations (chrome-devtools-mcp + burp-suite-mcp)",
      description:
        "Verify every external MCP integration is actually present/connected: chrome-devtools-mcp (stdio — installed or npx auto-install) and burp-suite-mcp (SSE — only alive when Burp is running with the extension loaded). Returns availability + fix hints, so you know before you need them.",
      inputSchema: {},
    },
    async () => {
      const status = await checkMcpServers();
      return { content: [{ type: "text", text: JSON.stringify({ mcp_servers: status }) }] };
    },
  );

  server.registerTool(
    "install_all_tools",
    {
      title: "Install every catalog tool at once",
      description:
        "CATALOG: install every non-MCP-server catalog tool in parallel (bounded concurrency), skipping MCP servers (they are connected, not installed). Returns a summary (installed / already_installed / failed) + per-tool result. Optionally filter by category (recon, web, api, cloud, system, ...). Use this to mass-provision the toolbelt instead of ensure_tool one-by-one.",
      inputSchema: {
        category: z.string().optional().describe("Only install tools in this category"),
        concurrency: z.number().int().min(1).max(16).optional().describe("Parallel install workers (default 4)"),
      },
    },
    async ({ category, concurrency }) => {
      const r = await installAllTools({ category, concurrency });
      return { content: [{ type: "text", text: JSON.stringify(r) }] };
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
    "attack_plan",
    {
      title: "Prioritized attack-vector plan for a target",
      description:
        "DECISION: return the prioritized attack-vector plan for a target — the vectors to test (injection vectors always listed, then param/tech hints add + reprioritize), each with a reason, the specific tool, a DERIVED success_probability (relevance prior) and estimated_time_sec. Pass mode: full (all vectors) / quick (priority<=2 only) / stealth (passive/config vectors only). Call this AFTER run_engagement recon to decide what to test next with data instead of guessing.",
      inputSchema: {
        target: z.string().describe("Target URL/host"),
        tech: z.array(z.string()).optional().describe("Detected technologies (from recon)"),
        params: z.array(z.string()).optional().describe("Discovered input parameters (from recon)"),
        mode: z.enum(["full", "quick", "stealth"]).optional().describe("Plan mode: full (default) / quick (top-priority only) / stealth (passive vectors only)"),
      },
    },
    async ({ target, tech, params, mode }) => {
      return { content: [{ type: "text", text: JSON.stringify(_attackPlan(target, tech ?? [], params ?? [], (mode as "full" | "quick" | "stealth") ?? "full")) }] };
    },
  );

  server.registerTool(
    "intelligence",
    {
      title: "Query the empirical intelligence ledger",
      description:
        "INTELLIGENCE: query the cross-engagement empirical ledger — hit-rates per (vector, tech), top vectors for a tech, or raw query. Verdicts are recorded AUTOMATICALLY by strike_resolve (confirmed/false_positive). Use this to learn what historically worked on a tech BEFORE planning, so a new Laravel target inherits the hit-rates of past Laravel engagements.",
      inputSchema: {
        action: z.enum(["hit_rates", "top_vectors", "query"]).describe("hit_rates (aggregate) / top_vectors (ranked for a tech) / query (raw filter)"),
        tech: z.string().optional().describe("Tech/framework filter (e.g. flask, laravel, wordpress)"),
        vector: z.string().optional().describe("Vector filter (e.g. sql_injection)"),
        outcome: z.string().optional().describe("Outcome filter (confirmed/false_positive)"),
      },
    },
    async ({ action, tech, vector, outcome }) => {
      const out =
        action === "hit_rates" ? hitRates(tech)
        : action === "top_vectors" ? topVectors(tech ?? "unknown", 10)
        : queryIntel({ vector, tech, outcome });
      return { content: [{ type: "text", text: JSON.stringify(out) }] };
    },
  );

  server.registerTool(
    "compliance",
    {
      title: "Map CWE(s) to compliance frameworks",
      description:
        "COMPLIANCE: map a CWE (or a JSON array of CWEs from findings) to OWASP Top 10 (2021), OWASP ASVS v4.0, PCI DSS v4.0, ISO 27001:2022 Annex A, and NIST SP 800-53. Pass a single `cwe` for one mapping, or `cwes` (JSON array) for an aggregate summary. Tells a CISO/auditor which controls a finding violates.",
      inputSchema: {
        cwe: z.string().optional().describe("A single CWE id (e.g. CWE-89 or 89)"),
        cwes: z.string().optional().describe("JSON array of CWE ids for an aggregate summary"),
      },
    },
    async ({ cwe, cwes }) => {
      if (cwes) {
        let arr: string[];
        try { arr = JSON.parse(cwes); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid cwes JSON" }) }] }; }
        return { content: [{ type: "text", text: JSON.stringify(complianceSummary(arr)) }] };
      }
      const m = complianceMap(cwe ?? "");
      if (!m) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "CWE not in the compliance table", cwe, hint: "supported ids: 79, 89, 78, 94, 918, 611, 502, 22, 601, 434, 942, 287, 1336, 915, 1321, 352, 319, 693, 200, 862, 639, 640, 798, 327, 306" }) }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(m) }] };
    },
  );

  server.registerTool(
    "security_state",
    {
      title: "Analyze a sanitizer flow (security-state lattice)",
      description:
        "SECURITY-STATE: given a value's sanitizer/validator functions + the sink type it reaches, return the deterministic verdict — vulnerable (wrong-context sanitization / pseudo-sanitizer / raw taint) or safe (correct context / validated). This is the step beyond binary taint: it catches 'sanitized for X but used in a Y sink'. The lattice is data-driven, no guesses.",
      inputSchema: {
        sanitizers: z.string().optional().describe("JSON array of sanitizer/validator function names applied to the value (e.g. [\"sanitize_text_field\"])"),
        sink_type: z.string().describe("Sink type: sql_execution, code_execution, command_execution, deserialization, file_operations, redirect, html_render"),
      },
    },
    async ({ sanitizers, sink_type }) => {
      let arr: string[] = [];
      try { arr = sanitizers ? JSON.parse(sanitizers) : []; } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid sanitizers JSON" }) }] }; }
      return { content: [{ type: "text", text: JSON.stringify(analyzeSecurityState({ sanitizers: arr, sinkType: sink_type })) }] };
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
      const tracked = _trackHypothesis(sink, status);
      // PROOF-OBLIGATION: a pending hypothesis is an OPEN debt that must be
      // discharged (verified/refuted/blocked) before the engagement is complete.
      if ((status ?? "pending") === "pending") {
        createObligation({ claim: sink, correlation_id: String((tracked as { id?: string })?.id ?? "") });
      }
      return { content: [{ type: "text", text: JSON.stringify(tracked) }] };
    },
  );

  server.registerTool(
    "next_obligation",
    {
      title: "Get the next open proof obligation",
      description:
        "PROOF-OBLIGATION (single-decision loop): return the top OPEN hypothesis that still needs verification + the exact deterministic test to discharge it. The LLM asks, executes that one test, then calls discharge_obligation. Never plan from scratch — the ledger is the single source of truth for what work remains.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_nextObligation()) }] };
    },
  );

  server.registerTool(
    "discharge_obligation",
    {
      title: "Discharge a proof obligation",
      description:
        "PROOF-OBLIGATION: mark an open obligation as verified (evidence-backed), refuted (false positive), or blocked. Pass the obligation id (from next_obligation) OR a correlation_id. verified means you ran strike_verify and the marker reflected + negative control inert. When the last obligation is discharged the engagement is COMPLETE.",
      inputSchema: {
        id: z.string().optional().describe("Obligation id (from next_obligation / obligations)"),
        correlation_id: z.string().optional().describe("Correlation id (a finding/hypothesis id)"),
        status: z.enum(["verified", "refuted", "blocked"]).describe("Outcome of the verification"),
        note: z.string().optional().describe("Short note (e.g. evidence reference)"),
      },
    },
    async ({ id, correlation_id, status, note }) => {
      return { content: [{ type: "text", text: JSON.stringify(_dischargeObligation({ id, correlation_id, status, note })) }] };
    },
  );

  server.registerTool(
    "obligations",
    {
      title: "List all proof obligations",
      description:
        "PROOF-OBLIGATION: list the obligation ledger — open/verified/refuted/blocked counts + the open obligations. The `complete` flag is the deterministic gate: an engagement is NOT complete while open > 0.",
      inputSchema: {},
    },
    async () => {
      return { content: [{ type: "text", text: JSON.stringify(_listObligations()) }] };
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

  // --- ORCHESTRATION OPS (planning / delegation / worktree / watchdog / prune) ---

  server.registerTool(
    "plan",
    {
      title: "Generate an engagement plan",
      description:
        "ORCHESTRATION: generate the deterministic engagement plan (phase order, tool per phase, evidence required, risk, permission) for a target + mode. This is the planning pass (like a planning sub-agent) — call ONCE at the start, then execute without re-planning.",
      inputSchema: {
        target: z.string().describe("Target (path or URL) — for context"),
        mode: z.string().optional().describe("Engagement mode"),
        state: z.string().optional().describe("Current phase (default: plan)"),
      },
    },
    async ({ target, mode, state }) => {
      const executedState = (state ?? "plan") as Parameters<typeof buildPlan>[2];
      const plan = buildPlan(true, mode ?? "bug-bounty", executedState);
      const guidance = computeGuidance(executedState, true);
      return { content: [{ type: "text", text: JSON.stringify({ target, mode: mode ?? "bug-bounty", plan, guidance }, null, 2) }] };
    },
  );

  server.registerTool(
    "delegate",
    {
      title: "Plan subagent delegation (parallel-first)",
      description:
        "ORCHESTRATION: decompose a workstream list into parallel-first dispatch batches (named dependencies only) + the retry pattern. Fire every batch in ONE message; sequential is the exception. Returns batches so the LLM dispatches without re-deriving the dependency graph.",
      inputSchema: {
        tasks: z
          .array(
            z.object({
              id: z.string(),
              objective: z.string(),
              depends_on: z.array(z.string()).optional(),
            }),
          )
          .describe("Workstreams to delegate"),
      },
    },
    async ({ tasks }) => {
      const { batches, total } = decomposeBatches(tasks);
      return { content: [{ type: "text", text: JSON.stringify({ total, batches, retry: retryPattern("a workstream") }, null, 2) }] };
    },
  );

  server.registerTool(
    "task_start",
    {
      title: "Register a task with a checkpointed plan",
      description:
        "ORCHESTRATION: register a delegated workstream with an ordered plan (steps). Every step records a checkpoint so a failed workstream can be RESUMED from its last completed step instead of restarting. On-disk, so checkpoints survive restarts.",
      inputSchema: {
        task_id: z.string().describe("Unique task id (e.g. 'recon-api', 'audit-auth')"),
        objective: z.string().describe("What the task must accomplish"),
        plan: z.array(z.string()).describe("Ordered steps (e.g. ['recon','analyze','verify','report'])"),
      },
    },
    async ({ task_id, objective, plan }) => {
      return { content: [{ type: "text", text: JSON.stringify(taskStart(task_id, objective, plan), null, 2) }] };
    },
  );

  server.registerTool(
    "task_checkpoint",
    {
      title: "Record a task checkpoint",
      description:
        "ORCHESTRATION: record a checkpoint for a task step (in_progress / done / failed / blocked) with an optional note + output hash. Advancing 'done' moves current_step forward; a 'failed' checkpoint marks the task for resume.",
      inputSchema: {
        task_id: z.string().describe("Task id"),
        step: z.string().describe("Step name (must be in the plan)"),
        status: z.enum(["in_progress", "done", "failed", "blocked"]).describe("Checkpoint status"),
        note: z.string().optional().describe("What happened at this step"),
        output_hash: z.string().optional().describe("Hash of the artifacts produced (for resume dedup)"),
      },
    },
    async ({ task_id, step, status, note, output_hash }) => {
      return { content: [{ type: "text", text: JSON.stringify(taskCheckpoint(task_id, step, status, note, output_hash), null, 2) }] };
    },
  );

  server.registerTool(
    "task_status",
    {
      title: "Read a task's checkpoint state",
      description:
        "ORCHESTRATION: read a task's current state — status, current step, progress (done/total), remaining steps, and full checkpoint history. The orchestrator's deterministic view of where each workstream is.",
      inputSchema: {
        task_id: z.string().describe("Task id"),
      },
    },
    async ({ task_id }) => {
      return { content: [{ type: "text", text: JSON.stringify(taskStatus(task_id), null, 2) }] };
    },
  );

  server.registerTool(
    "task_resume",
    {
      title: "Resume a task from its last checkpoint",
      description:
        "ORCHESTRATION: compute the resume instruction for a failed/blocked task — the last completed checkpoint, the current step, the remaining steps, and the exact re-dispatch prompt (resume from where it stopped, not a fresh start).",
      inputSchema: {
        task_id: z.string().describe("Task id"),
      },
    },
    async ({ task_id }) => {
      return { content: [{ type: "text", text: JSON.stringify(taskResume(task_id), null, 2) }] };
    },
  );

  server.registerTool(
    "worktree",
    {
      title: "Isolate a git worktree",
      description:
        "ORCHESTRATION: create/list/remove an isolated git worktree so parallel workstreams don't conflict on the same files. add: `git worktree add -b <branch> <path>`; list: enumerate existing; remove: clean up after a workstream.",
      inputSchema: {
        action: z.enum(["add", "list", "remove"]).describe("Operation"),
        path: z.string().optional().describe("Path (for add/remove)"),
        branch: z.string().optional().describe("Branch name (for add; default auto)"),
      },
    },
    async ({ action, path, branch }) => {
      return { content: [{ type: "text", text: JSON.stringify(worktree(action, path, branch)) }] };
    },
  );

  server.registerTool(
    "watchdog",
    {
      title: "Check engagement health (stall detection)",
      description:
        "ORCHESTRATION: detect a stalled phase — no progress (idle > 15 min, no hypotheses). Returns STALLED / PROGRESSING / IDLE plus the concrete intervention so the LLM unblocks instead of looping.",
      inputSchema: {
        phase: z.string().describe("Current phase"),
        hypotheses: z.number().int().describe("Number of tracked hypotheses"),
        last_activity_ms: z.number().int().describe("Timestamp (ms) of last activity"),
      },
    },
    async ({ phase, hypotheses, last_activity_ms }) => {
      return { content: [{ type: "text", text: JSON.stringify(watchdog(phase, hypotheses, last_activity_ms)) }] };
    },
  );

  server.registerTool(
    "context_prune",
    {
      title: "Compact the engagement state",
      description:
        "ORCHESTRATION: produce a compact summary (phase, confirmed/pending/rejected counts, top findings) so the LLM can DROP raw detail from its context and keep only this. The engagement tracker is the source of truth — re-read it instead of relying on memory.",
      inputSchema: {
        phase: z.string().describe("Current phase"),
        findings: z.array(z.record(z.string(), z.unknown())).describe("Findings to compact"),
      },
    },
    async ({ phase, findings }) => {
      return { content: [{ type: "text", text: JSON.stringify(compactState(phase, findings)) }] };
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
        "FINDINGS: create a canonical, evidence-first finding. Severity describes impact; confidence (deterministic) describes certainty. Default status=detected (hypothesis-pending). Pass `evidence` (JSON array of {type, description, content}) to attach observed artifacts AT CREATION — a finding must never be born empty when you already hold the artifact (headers, URL, response body).",
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
        evidence: z.string().optional().describe("JSON array of evidence entries: [{type, description, content?}] — attached at creation (redacted + SHA-256 tagged)"),
      },
    },
    async ({ title, target_type, host, endpoint, severity, cwe, source_type, source_name, sink_type, sink_symbol, chain_id, evidence }) => {
      let evs: Array<{ type: string; description: string; content?: string }> = [];
      if (evidence) {
        try { evs = JSON.parse(evidence); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid evidence JSON" }) }] }; }
      }
      const f = makeFinding({
        title,
        target: { type: (target_type as FindingTarget["type"]) ?? "web", host, endpoint },
        severity: (severity as Severity) ?? "medium",
        cwe,
        source: { type: source_type, name: source_name },
        sink: { type: sink_type, symbol: sink_symbol },
        chainId: chain_id ?? null,
        status: "detected",
        evidence: evs as Array<{ type: EvidenceType; description: string; content?: string }>,
      });
      const empty = (f.evidence ?? []).length === 0;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...f,
            _warning: empty ? "finding created with NO evidence — if you hold the observed artifact (headers/URL/body), attach it now via `evidence` or finding_attach_evidence" : undefined,
          }),
        }],
      };
    },
  );

  server.registerTool(
    "finding_transition",
    {
      title: "Advance a finding lifecycle (STATEFUL)",
      description:
        "FINDINGS: advance a canonical Finding through its lifecycle (detected->triaged->hypothesis->validating->confirmed) and RETURN the updated finding. STATEFUL — pass the FULL finding JSON (from finding_create / run_engagement), not a status string. Rejects illegal transitions with the legal next states. Confirmed is terminal. To confirm FROM a live verdict use strike_resolve instead.",
      inputSchema: {
        finding: z.string().describe("JSON of the canonical Finding object (from finding_create / run_engagement)"),
        to: z.string().describe("Target status (triaged/hypothesis/validating/confirmed/false_positive/rejected/blocked/out_of_scope)"),
      },
    },
    async ({ finding, to }) => {
      let f: Finding;
      try { f = JSON.parse(finding); } catch { return { content: [{ type: "text", text: JSON.stringify({ error: "invalid finding JSON — pass the full Finding object, not a status string" }) }] }; }
      const from = f.status ?? "detected";
      if (!_canTransition(from, to as FindingStatus)) {
        return { content: [{ type: "text", text: JSON.stringify({ error: `illegal transition ${from} -> ${to}`, from, legal_next: _LIFECYCLE[from] ?? [] }) }] };
      }
      const updated = _transition(f, to as FindingStatus);
      const terminal = (_LIFECYCLE[updated.status] ?? []).length === 0;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            ...updated,
            transition: `${from} -> ${updated.status}`,
            ...(terminal ? { hint: "TERMINAL state reached. A 'confirmed' claim must be evidence-backed (strike_verify -> strike_resolve); otherwise treat it as unverified. Then generate_report." } : { next: _LIFECYCLE[updated.status] ?? [] }),
          }),
        }],
      };
    },
  );

  server.registerTool(
    "capture_false_positive",
    {
      title: "Capture a verified false positive (self-hardening)",
      description:
        "SELF-HARDENING: record a VERIFIED false positive (a code pattern the detector flagged but live verification ruled out) into the writable benchmark corpus, so the next run_benchmark measures whether the detector STILL flags it. Pass the triggering CODE + language + detector + a short note. Every capture makes the detector more precise — close the loop, never just discard a refuted lead.",
      inputSchema: {
        code: z.string().describe("The code snippet that triggered the false detection"),
        language: z.string().describe("Language: php/javascript/typescript/python/java"),
        detector: z.enum(["taint", "complex_bugs", "route_confusion"]).optional().describe("Which detector flagged it"),
        note: z.string().optional().describe("Short note on why it was a false positive"),
        sink_type: z.string().optional().describe("The sink type the detector claimed"),
      },
    },
    async ({ code, language, detector, note, sink_type }) => {
      const r = captureFalsePositive({ code, language, detector: detector as "taint" | "complex_bugs" | "route_confusion" | undefined, note, sink_type });
      return { content: [{ type: "text", text: JSON.stringify({ saved: r.path, id: r.entry.id, hint: "Captured as a safe corpus entry. Re-run run_benchmark — if it shows still_flagged, that detector needs a suppression." }) }] };
    },
  );

  server.registerTool(
    "confidence_score",
    {
      title: "Compute deterministic confidence",
      description:
        "FINDINGS: compute a deterministic weighted confidence score (static/data-flow/reachability/preconditions/validation/negative-control). Never an AI opinion. DETERMINISTIC — identical inputs give the identical score, so never retry with the same factors. The score does NOT change a finding; use strike_resolve (finding + verdict) to attach a confidence + advance the lifecycle.",
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
      return { content: [{ type: "text", text: JSON.stringify({ score, level: _confidenceLevel(score), note: "deterministic — same factors = same score; do not retry. Attach to a finding via strike_resolve." }) }] };
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
      title: "Complex-bug scan (deserialization / type juggling / mass assignment / prototype pollution / CRLF / path confusion / SSRF / XXE / SSTI / wrong-context sanitization)",
      description:
        "Complex-bug detection beyond taint: deserialization→POP gadget chain (unserialize + magic method), type juggling (loose ==/!= vs hash/secret), mass assignment (extract/parse_str without a safe flag), prototype pollution (unsafe merge of request data), CRLF/header injection (user input into a header), path confusion (user input into a file path without canonicalization), SSRF (user-controlled URL with no host allowlist), XXE (user XML parsed without disabling entities), SSTI (user input into a template render with no sandbox), and wrong-context sanitization (a value sanitized for context X reaching a sink that needs Y — e.g. sanitize_text_field() into a SQL query).",
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
        "REPORT: the FINAL deliverable — emit a deterministic HackerOne-grade markdown (or JSON) report from your confirmed Findings: executive summary + summary table + per-finding description/root-cause/steps-to-reproduce/impact/remediation/references + CVSS vector + recommendations + appendix. Call this at the END of every engagement instead of hand-writing a surface/recon map. Reproducible: same findings -> byte-identical output.",
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
      const fmt = format ?? "markdown";
      const opts = { title, scope, version: VERSION };
      const out = fmt === "json" ? reportJson(list, opts) : reportMarkdown(list, opts);
      // Persist to the reports dir — an engagement must produce an on-disk .md/.json deliverable.
      const saved = saveReport(out, { title, scope, version: VERSION, format: fmt });
      // PROOF-OBLIGATION GATE: an engagement is NOT complete while open proof debt remains.
      const open = _openCount();
      const gate = open > 0
        ? `\n\n⚠ PROOF-OBLIGATION GATE: ${open} open obligation(s) remain unverified. Discharge them (next_obligation -> strike_verify -> discharge_obligation) before declaring the engagement complete.\n`
        : "";
      return { content: [{ type: "text", text: `Report saved to: ${saved.path}\n\n${out}${gate}` }] };
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
