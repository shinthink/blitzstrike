// Ad-hoc verification for BlitzStrike TypeScript final state.
// Runs the real modules end-to-end (no MCP wire needed for logic), then the
// binary compile + MCP stdio handshake as separate shell steps.
import { scanFile, traceFunction, grepInFunctions, iterSourceFiles } from "../src/scanner.ts";
import { scopeCheck, enrichScan, runEngagement, listChains, loadChains } from "../src/orchestrator.ts";
import { nvdLookup } from "../src/recon.ts";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve repo root relative to THIS file so the suite is hermetic (CI clones
// to an arbitrary path, never /root/...).
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const results: Array<[string, boolean, string]> = [];
function check(name: string, cond: boolean, detail = "") {
  results.push([name, cond, detail]);
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}  ${detail}`);
}

// 1. data layer
const chains = loadChains();
check("chains.json 57 chains (22 own + 35 merged)", chains.length === 57, `got ${chains.length}`);
check("listChains 57", (listChains() as any).total === 57);

// 2. scanner on a hermetic fixture (committed, no external path)
const target = join(ROOT, "test", "fixtures", "upload-target");
const files = iterSourceFiles(target, 2000);
check("iterSourceFiles > 0", files.length > 0, `got ${files.length}`);
check("only php-family", files.every((f) => f.endsWith(".php")), `${files.length} php`);

let uploadFile: string | null = null;
for (const f of files) {
  if (scanFile(f).sinks.some((s) => s.sink.includes("move_uploaded_file"))) { uploadFile = f; break; }
}
check("scanFile finds upload sink", uploadFile !== null, uploadFile ?? "none");

// 2b. comment-stripping: a sink token inside a comment must NOT be reported
import { writeFileSync as _wfs, rmSync as _rms } from "node:fs";
const _tmpC = join(ROOT, "test", "fixtures", "comment-sink-fixture.php");
_wfs(_tmpC, "<?php\n// use extract($_REQUEST);\nextract($_REQUEST);\n// /* system($_GET['x']); */\n$u = \"https://example.com/system(\";\n");
const _cs = scanFile(_tmpC);
const _extractLines = _cs.sinks.filter((s) => s.sink === "extract(").map((s) => s.line);
check("scanFile ignores sink tokens in comments (and inside strings)", _extractLines.length === 1 && _extractLines[0] === 3 && !_cs.sinks.some((s) => s.sink === "system("), `extract@${_extractLines.join(",")} sinks=${_cs.sinks.map((s) => s.sink).join(",")}`);
_rms(_tmpC, { force: true });

// 2c. breadth scanner covers Laravel static DB facade (DB::select / whereRaw)
_wfs(_tmpC, "<?php\n$q = $request->input('q');\n$rows = DB::select(\"SELECT * FROM users WHERE name = '$q'\");\n$n = DB::raw($q);\n");
const _ls = scanFile(_tmpC);
const _lsSinks = _ls.sinks.map((s) => s.sink);
check("scanFile finds DB::select + DB::raw", _lsSinks.includes("DB::select(") && _lsSinks.includes("DB::raw("), _lsSinks.join(","));
_rms(_tmpC, { force: true });

// 3. anti-grep-monkey + trace
if (uploadFile) {
  const tr = traceFunction(uploadFile, "handle_upload");
  check("traceFunction no-crash", tr.definition_count >= 0, `defs=${tr.definition_count}`);
}
const gh = grepInFunctions(target, "move_uploaded_file(", 20);
check("grepInFunctions in-function hits", gh.length >= 1, `hits=${gh.length}`);

// 4. scope enforcement
check("scope blocked", scopeCheck("https://evil.com", "example.com", "bug-bounty").allowed === false);
check("scope allowed", scopeCheck("https://api.example.com", "example.com", "bug-bounty").allowed === true);
check("scope exclusion", scopeCheck("https://internal.example.com", "example.com, -internal.example.com", "bug-bounty").allowed === false);
check("scope ctf off", scopeCheck("https://x", "", "ctf").allowed === true);
check("scope: filesystem path always in-scope", scopeCheck("/root/some/src", "", "bug-bounty").allowed === true && (scopeCheck("/root/some/src", "", "bug-bounty").reason ?? "").includes("in-scope"));
check("scope: relative path always in-scope", scopeCheck("./vendor/app", "", "bug-bounty").allowed === true);

// 5. engagement
const es = enrichScan(target) as any;
check("enrichScan matched chains", es.matched_chains.length >= 1, `matched=${es.matched_chains.length}`);

const re = runEngagement(target, "", "bug-bounty") as any;
check("engagement COMPLETE", re.status === "COMPLETE" && re.scope.enforcement === "source-audit");
check("engagement hypothesis findings", re.findings.length >= 1 && re.findings.every((f: any) => f.status === "hypothesis"), `n=${re.findings.length}`);
check("engagement findings carry evidence + confidence", re.findings.every((f: any) => f.evidence_count >= 1 && typeof f.confidence === "number" && typeof f.confidence_level === "string"), `first=${JSON.stringify(re.findings[0] ?? {}).slice(0, 120)}`);
check("engagement URL blocked", (runEngagement("https://evil.com", "", "bug-bounty") as any).status === "BLOCKED");

// 6. NVD lookup — structural check (no hard network dependency: a live call may
// be rate-limited/unreachable in CI, but the result must always be structured)
try {
  const nvd = await nvdLookup("CVE-2026-61424");
  check("nvdLookup returns structured result", typeof (nvd as any).found === "boolean", JSON.stringify(nvd).slice(0, 60));
} catch (e) {
  check("nvdLookup returns structured result", false, String(e));
}

// 7. catalog breadth layer (tools + skills)
import { toolLookup, listTools, skillLookup, listSkills, readSkill } from "../src/catalog.ts";
const tl = toolLookup("sqlmap") as any;
check("toolLookup sqlmap", tl.found === true && tl.tool.command === "sqlmap");
const lt = listTools() as any;
check("listTools 130 tools", lt.total >= 130, `got ${lt.total}`);
check("listTools has RE+blue+AD domains",
      lt.categories["reverse-engineering"] && lt.categories["blue-team"] && lt.categories["active-directory"],
      Object.keys(lt.categories).join(","));
const ghidra = toolLookup("ghidra") as any;
check("toolLookup ghidra (RE domain)", ghidra.found === true && ghidra.tool.category === "reverse-engineering");
const sl2 = skillLookup("kerberos") as any;
check("skillLookup kerberos -> AD", sl2.found === true && sl2.matches[0].name.includes("kerberos"));
const ls = listSkills() as any;
check("listSkills 32 third-party skills (ap-* + hp-*)", ls.total >= 32, `got ${ls.total}`);
const rs = readSkill("ap-cross-forest-trust-abuse") as any;
check("readSkill content (adversary-playbook)", rs.found === true && rs.content.length > 500, `chars=${rs.content?.length}`);
const gem = readSkill("ap-cross-forest-trust-abuse") as any;
check("readSkill hidden gem (adversary-playbook)", gem.found === true && gem.content.length > 500, `chars=${gem.content?.length}`);
const gem2 = readSkill("hp-full-security-audit") as any;
check("readSkill hidden gem (hack.proof)", gem2.found === true && gem2.content.length > 500, `chars=${gem2.content?.length}`);

// 8. manual layer (deep tool reference + playbooks, wired into flow)
import { findManual, readPlaybook, listManuals, manualForTool } from "../src/manuals.ts";
const fm = findManual("sqlmap") as any;
check("findManual sqlmap (270+ manuals)", fm.found === true && fm.content.length > 1000, `chars=${fm.content?.length}`);
const lm2 = listManuals() as any;
check("listManuals 270 tools + 17 playbooks", lm2.total_tools >= 270 && lm2.total_playbooks >= 17, `${lm2.total_tools}/${lm2.total_playbooks}`);
const pb = readPlaybook("web-application") as any;
check("readPlaybook web-application", pb.found === true && pb.content.length > 5000, `chars=${pb.content?.length}`);
const mf = manualForTool("ffuf");
check("manualForTool ffuf (wired into tool_lookup)", mf !== null && mf.content.length > 1000, `chars=${mf?.content?.length}`);
const mfBad = manualForTool("nonexistent-tool-xyzzy");
check("manualForTool nonexistent -> null (no false fuzzy match)", mfBad === null, `got ${mfBad?.name ?? "null"}`);

// 9. ensure_tool install-path logic: not-installed signal is exit 127 (not flag exit code)
import { ensureTool, loadTools } from "../src/catalog.ts";
const curlEnsure = ensureTool("curl") as any;
check("ensureTool curl -> installed (curl is ubiquitous)", curlEnsure.installed === true && curlEnsure.action === "none", `action=${curlEnsure.action}`);
const sqlmapEnsure = ensureTool("sqlmap") as any;
check("ensureTool sqlmap -> deterministic result (installed OR install action)", typeof sqlmapEnsure.installed === "boolean" && (sqlmapEnsure.action === "none" || sqlmapEnsure.action === "install"), `action=${sqlmapEnsure.action}`);
const gitleaksEnsure = ensureTool("gitleaks") as any;
check("ensureTool gitleaks -> deterministic result (installed OR install action)", typeof gitleaksEnsure.installed === "boolean" && (gitleaksEnsure.action === "none" || gitleaksEnsure.action === "install"), `action=${gitleaksEnsure.action}`);
const totalTools = loadTools().length;
check("loadTools 130 tools", totalTools >= 130, `got ${totalTools}`);

// 10. intelligence data layer (WAF + tech/CVE/port correlations + fuzzer)
import { detectWaf, techCorrelation, cveCorrelation, portCorrelation, intelSummary } from "../src/intel.ts";
const wafHit = detectWaf({ "cf-ray": "x", server: "cloudflare" }, "") as any;
check("detectWaf cloudflare (header-name match)", wafHit.detected === true && wafHit.wafs[0].waf === "Cloudflare", wafHit.wafs?.[0]?.waf ?? "none");
const wafMiss = detectWaf({ "x-powered-by": "PHP" }, "") as any;
check("detectWaf no false positive (php-only)", wafMiss.detected === false, `wafs=${wafMiss.wafs?.length ?? 0}`);
const tech = techCorrelation("wordpress") as any;
check("techCorrelation wordpress", tech.found === true && (tech.vulns ?? []).length > 0);
const cve = cveCorrelation("CVE-2021-44228") as any;
check("cveCorrelation Log4Shell", cve.found === true && cve.name === "Log4Shell");
const port = portCorrelation("445") as any;
check("portCorrelation 445 (SMB)", port.found === true && port.service === "SMB");
const isum = intelSummary() as any;
check("intelSummary (139 waf + 89 tech + 103 port)", isum.waf_signatures >= 100 && isum.tech_correlations >= 50 && isum.port_correlations >= 100, JSON.stringify(isum));

// 10b. attack-vector taxonomy (BLITZ attack-surface mapping)
import { listAttackVectors, attackVectors } from "../src/intel.ts";
const _avList = listAttackVectors() as any;
check("attack-vector taxonomy 34 categories + 588 vectors", _avList.total_categories === 34 && _avList.total_vectors >= 580, `cats=${_avList.total_categories} vecs=${_avList.total_vectors}`);
const _avSsrF = attackVectors("ssrf") as any;
check("attackVectors ssrf -> 16 vectors", _avSsrF.found === true && _avSsrF.count >= 15, `count=${_avSsrF.count}`);
check("attackVectors fuzzy 'business logic' -> found", (attackVectors("business logic") as any).found === true, "fuzzy");
check("intelSummary counts attack vectors", isum.attack_vector_categories === 34 && isum.attack_vectors >= 580, `cats=${isum.attack_vector_categories} vecs=${isum.attack_vectors}`);

// 11. payload collections + nuclei templates (PayloadsAllTheThings + nuclei-templates, MIT)
import { payloadLookup, readPayload, templateLookup, listPayloadCategories } from "../src/intel.ts";
check("payload categories 60+ (PayloadsAllTheThings)", listPayloadCategories().length >= 60, `got ${listPayloadCategories().length}`);
const pl = payloadLookup("sqli") as any;
check("payloadLookup sqli -> SQL Injection", pl.found === true && pl.category === "SQL Injection", pl.category ?? "none");
const pl2 = payloadLookup("ssrf") as any;
check("payloadLookup ssrf (alias)", pl2.found === true && pl2.category === "Server Side Request Forgery", pl2.category ?? "none");
const tl2 = templateLookup("CVE-2021-44228", 5) as any;
check("templateLookup log4shell (11.9k templates)", tl2.found === true && tl2.count >= 1, `count=${tl2.count}`);

// 12. active_scan approval gate (gated without authorization)
import { activeScan } from "../src/active.ts";
const asGate = await activeScan("https://example.com", "", "bug-bounty", false) as any;
check("activeScan gated without authorization", asGate.gated === true, `gated=${asGate.gated}`);

// 13. Finding engine — canonical schema + lifecycle + severity/confidence
import {
  makeFinding, transition, canTransition, confirmFinding,
  computeConfidence, confidenceLevel, SEVERITY_RANK,
} from "../src/finding.ts";
const f0 = makeFinding({
  title: "Test SQLi",
  target: { type: "web", host: "example.com", endpoint: "/x" },
  severity: "high",
  cwe: "CWE-89",
  source: { type: "request_parameter", name: "id" },
  sink: { type: "sql_execution", symbol: "->query(" },
  chainId: "sql_injection",
  status: "detected",
});
check("finding canonical id BS-*", f0.id.startsWith("BS-") && f0.status === "detected");
check("finding severity high + confidence static-only", f0.classification.severity === "high" && f0.confidence === 0.20 && f0.confidence_level === "informational", `conf=${f0.confidence} lvl=${f0.confidence_level}`);
check("lifecycle detected->triaged ok", canTransition("detected", "triaged") === true);
check("lifecycle confirmed terminal", canTransition("confirmed", "false_positive") === false);
check("lifecycle hypothesis->validating ok", canTransition("hypothesis", "validating") === true);
const f1 = transition(f0, "triaged");
const f2 = transition(f1, "hypothesis");
check("transition chain advances", f2.status === "hypothesis", f2.status);
check("illegal transition throws", (() => { try { transition(f0, "confirmed"); return false; } catch { return true; } })() === true);

// 14. Evidence engine — integrity + redaction
import { makeEvidence as mkEv, redactSecrets, sha256, verifyEvidence } from "../src/evidence.ts";
const dirty = "Authorization: Bearer abcDEF1234567890\npassword=supersecret123";
const clean = redactSecrets(dirty);
check("redact bearer + password", !clean.includes("abcDEF1234567890") && !clean.includes("supersecret123") && clean.includes("[REDACTED]"), clean.slice(0, 60));
const ev2 = mkEv({
  type: "validation_result",
  description: "marker reflected",
  artifacts: [{ name: "resp", kind: "http", content: "Authorization: Bearer secretsecret12345" }],
});
check("evidence sha256 integrity", verifyEvidence(ev2).ok === true && ev2.artifacts[0].sha256 === sha256(ev2.artifacts[0].content));
check("evidence content redacted", ev2.artifacts[0].content.includes("[REDACTED]"), ev2.artifacts[0].content.slice(0, 50));
const conf = confirmFinding(f2, {
  baseline: true,
  negative_control: true,
  evidence: [{ type: "validation_result", description: "confirmed" }],
});
check("confirmFinding -> confirmed + confidence 1.0", conf.status === "confirmed" && conf.confidence === 1.0 && conf.validation.performed === true, `conf=${conf.confidence}`);

// 15. Confidence engine — deterministic weights
check("confidence full = 1.0", computeConfidence({ static_analysis: true, data_flow: true, reachability: true, preconditions: true, runtime_validation: true, negative_control: true }) === 1.0);
check("confidence none = 0.0", computeConfidence({}) === 0.0);
check("confidenceLevel 0.94 -> confirmed", confidenceLevel(0.94) === "confirmed");
check("confidenceLevel 0.55 -> likely", confidenceLevel(0.55) === "likely");
check("severity rank order", SEVERITY_RANK.critical < SEVERITY_RANK.high && SEVERITY_RANK.high < SEVERITY_RANK.medium);

// 15b. Phase 1 — Core Integrity: invariants + evidence provenance + audit events
import { checkFindingInvariants, isInvariantClean, assertFindingInvariants } from "../src/invariants.ts";
import { recordAudit, listAudit } from "../src/audit.ts";
// evidence provenance (§16)
const _prov = mkEv({ type: "request", description: "req", provenance: { tool: "strike", target: "x.com" } });
check("evidence carries provenance (tool+version+target)", _prov.provenance.tool === "strike" && typeof _prov.provenance.version === "string" && _prov.provenance.target === "x.com", JSON.stringify(_prov.provenance));
const _provDefault = mkEv({ type: "request", description: "req" });
check("evidence default provenance = blitzstrike", _provDefault.provenance.tool === "blitzstrike", _provDefault.provenance.tool);
// invariant: confirmed requires evidence
const _confNoEv = { ...f2, status: "confirmed" as const, evidence: [], validation: { performed: true, status: "confirmed" as const, negative_control: true } };
check("invariant: confirmed without evidence -> violation", checkFindingInvariants(_confNoEv).some((v) => v.invariant === "confirmed-requires-evidence"), "confirmed-no-evidence");
// invariant: confirmed with failed negative control
const _confBadNc = { ...f2, status: "confirmed" as const, evidence: [ev2], validation: { performed: true, status: "confirmed" as const, negative_control: false } };
check("invariant: confirmed with failed negative control -> violation", checkFindingInvariants(_confBadNc).some((v) => v.invariant === "confirmed-requires-clean-negative-control"), "bad-nc");
// invariant: confirmed out of scope
const _confOos = { ...f2, status: "confirmed" as const, evidence: [ev2], validation: { performed: true, status: "confirmed" as const, negative_control: true, scope_allowed: false } };
check("invariant: confirmed out of scope -> violation", checkFindingInvariants(_confOos).some((v) => v.invariant === "confirmed-requires-scope-allowed"), "out-of-scope");
// invariant: secret in evidence (RAW secret bypassing makeEvidence redaction)
const _rawSecretEv = {
  evidence_id: "EV-RAW",
  type: "response" as const,
  description: "resp",
  artifacts: [{ name: "r", kind: "http", content: "password=supersecret123", sha256: "x" }],
  recorded: "2026-01-01T00:00:00.000Z",
  provenance: { tool: "blitzstrike", version: "x" },
};
const _confSecret = { ...f2, status: "confirmed" as const, evidence: [_rawSecretEv], validation: { performed: true, status: "confirmed" as const, negative_control: true } };
check("invariant: raw secret in evidence -> violation", checkFindingInvariants(_confSecret).some((v) => v.invariant === "no-secret-in-evidence"), "secret");
// invariant: redacted content is NOT flagged (no false positive)
const _confRedacted = { ...f2, status: "confirmed" as const, evidence: [ev2], validation: { performed: true, status: "confirmed" as const, negative_control: true } };
check("invariant: redacted evidence NOT flagged as secret", !checkFindingInvariants(_confRedacted).some((v) => v.invariant === "no-secret-in-evidence"), "redacted-clean");
// hasSecrets determinism + no false-positive on redacted (regression)
import { hasSecrets as _hasSecrets } from "../src/evidence.ts";
const _det = [1, 2, 3, 4, 5].map(() => _hasSecrets("password=supersecret123"));
check("hasSecrets deterministic (g-flag lastIndex fix)", _det.every((b) => b === true), _det.join(","));
check("hasSecrets redacted -> false (no false positive)", _hasSecrets("password=[REDACTED]") === false, "redacted");
// invariant: clean confirmed finding passes
const _confClean = confirmFinding(f2, { evidence: [{ type: "validation_result", description: "ok" }] });
check("invariant: clean confirmed finding is invariant-clean", isInvariantClean(_confClean), JSON.stringify(checkFindingInvariants(_confClean)));
// confirmFinding throws without evidence
let _threwNoEv = false;
try { confirmFinding(f2, { evidence: [] }); } catch { _threwNoEv = true; }
check("confirmFinding throws without evidence", _threwNoEv, "no-throw");
// audit events
recordAudit("scope_checked", { target: "x.com", result: "allowed" });
const _audit = listAudit();
check("audit: recordAudit persists + listAudit reads", _audit.length >= 1 && _audit.some((a) => a.event === "scope_checked"), `len=${_audit.length}`);
check("audit record has timestamp + tool_version", _audit[0]?.timestamp !== undefined && _audit[0]?.tool_version !== undefined, JSON.stringify(_audit[0] ?? {}));

// 16. EAGLE-EYE data-flow engine (§7-11)
import { traceDataFlow, groupVariants, classifySink as _classifySink, classifySource as _classifySource, findSanitizers as _findSanitizers, isSanitized as _isSanitized } from "../src/dataflow.ts";
check("dataflow classifySink ->query = sql", _classifySink("->query(")?.id === "sql_execution", _classifySink("->query(")?.id ?? "null");
check("dataflow classifySink eval = code_exec", _classifySink("eval(")?.id === "code_execution", _classifySink("eval(")?.id ?? "null");
check("dataflow classifySource $_GET attacker-controlled", _classifySource("$_GET[\"id\"]")?.attacker_controlled === true && _classifySource("$_GET[\"id\"]")?.id === "http_get", _classifySource("$_GET[\"id\"]")?.id ?? "null");
check("dataflow sanitizer htmlspecialchars neutralizes html_render", _isSanitized(_findSanitizers("htmlspecialchars($_GET[x])"), "html_render") === true);
check("dataflow sanitizer esc_sql neutralizes sql", _isSanitized(_findSanitizers("$wpdb->prepare(\"SELECT...\")"), "sql_execution") === true);
const df = traceDataFlow(join(ROOT, "src", "server.ts"));
check("dataflow traceDataFlow returns structured buckets", Array.isArray(df.candidates) && Array.isArray(df.sanitized) && Array.isArray(df.authorized), `c=${df.candidates.length} s=${df.sanitized.length} a=${df.authorized.length}`);
const groups = groupVariants([df]);
check("dataflow groupVariants returns groups", Array.isArray(groups) && groups.every((g: any) => g.occurrences >= 1 && typeof g.root_cause === "string"), `groups=${groups.length}`);

// data-flow bucket correctness (§7-10): candidate vs sanitized vs authorized
import { writeFileSync } from "node:fs";
const dfFixture = "/tmp/df-vuln-fixture.php";
writeFileSync(dfFixture, `<?php
$id = $_GET['id'];
$wpdb->query("SELECT * FROM t WHERE id = $id");
$name = $_GET['name'];
echo htmlspecialchars($name);
$cmd = $_GET['cmd'];
if (check_ajax_referer('x','y')) { system($cmd); }
$num = $_GET['num'];
$wpdb->get_results("SELECT * FROM t WHERE n = " . intval($num));
`);
const dfr = traceDataFlow(dfFixture);
check("dataflow unsanitized SQL = candidate", dfr.candidates.length === 1 && dfr.candidates[0].sink?.id === "sql_execution", `candidates=${dfr.candidates.length}`);
check("dataflow sanitized XSS+intval = 2 sanitized", dfr.sanitized.length === 2 && dfr.sanitized.every((s: any) => s.sanitizers.length >= 1), `sanitized=${dfr.sanitized.length}`);
check("dataflow nonce-gated cmd exec = authorized", dfr.authorized.length === 1 && dfr.authorized[0].sink?.id === "command_execution", `authorized=${dfr.authorized.length}`);
check("dataflow no duplicate sink", (dfr.candidates.length + dfr.sanitized.length + dfr.authorized.length) === 4, `total=${dfr.candidates.length + dfr.sanitized.length + dfr.authorized.length} (expect 4 distinct sinks)`);

// 17. TAINT engine (§7 inter-procedural) — assignment + cross-function + sanitizer
import { analyzeTaint } from "../src/taint.ts";
const taintFixture = "/tmp/taint-fixture.php";
writeFileSync(taintFixture, `<?php
$id = $_GET['id'];
$wpdb->query("SELECT * FROM t WHERE id = $id");
$name = $_GET['name'];
echo htmlspecialchars($name);
function save_record($data) { global $wpdb; $wpdb->query("INSERT INTO log VALUES ('$data')"); }
$payload = $_GET['payload'];
save_record($payload);
function render($x) { echo htmlspecialchars($x); }
$html = $_GET['html'];
render($html);
`);
const tr = analyzeTaint(taintFixture);
check("taint direct SQLi detected", tr.findings.some((f: any) => f.sink_line === 3 && f.category === "SQL execution"), `findings=${tr.findings.length}`);
check("taint sanitized XSS suppressed", !tr.findings.some((f: any) => f.sink_line === 5), `suppressed=${tr.suppressed}`);
check("taint inter-procedural SQLi detected", tr.findings.some((f: any) => f.interprocedural === true && f.category === "SQL execution"), `interproc count=${tr.findings.filter((f: any) => f.interprocedural).length}`);
check("taint inter-procedural sanitized suppressed", !tr.findings.some((f: any) => f.sink_line >= 13 && f.category === "HTML rendering (XSS)"), `findings=${JSON.stringify(tr.findings.map((f: any) => f.sink_line))}`);
check("taint 2 findings + 2 suppressed", tr.findings.length === 2 && tr.suppressed === 2, `f=${tr.findings.length} s=${tr.suppressed}`);

// 17b. EAGLE-EYE 2.0 — whole-program interprocedural taint (Phase 2)
import { buildCallGraph as _buildCallGraph, reachableFrom as _reachableFrom } from "../src/callgraph.ts";
import { analyzeDataFlow2 } from "../src/eagle2.ts";
const _e2Fixture = join(ROOT, "test", "fixtures", "eagle2-target", "eagle2.php");
const _e2 = analyzeDataFlow2(_e2Fixture);
check("eagle2: call graph has functions + edges", _e2.summary.functions >= 5 && _e2.summary.edges >= 8, `f=${_e2.summary.functions} e=${_e2.summary.edges}`);
check("eagle2: return propagation XSS detected", _e2.findings.some((f: any) => f.sink_line === 29 && f.category === "HTML rendering (XSS)"), `findings=${_e2.findings.map((f: any) => f.sink_line).join(",")}`);
check("eagle2: byref alias command exec detected", _e2.findings.some((f: any) => f.sink_line === 36 && f.category === "Command execution"), "byref");
check("eagle2: ternary XSS detected", _e2.findings.some((f: any) => f.sink_line === 39 && f.category === "HTML rendering (XSS)"), "ternary");
check("eagle2: transitive interprocedural system detected", _e2.findings.some((f: any) => f.interprocedural === true && f.sink.includes("system(")), "transitive");
check("eagle2: auth-gated SQLi flagged auth_gated=true", _e2.findings.some((f: any) => f.auth_gated === true && f.auth_gates.includes("current_user_can")), "auth");
check("eagle2: unauth SQLi auth_gated=false", _e2.findings.some((f: any) => f.sink.includes("query(") && f.auth_gated === false), "unauth");
check("eagle2: sanitized echo suppressed", _e2.suppressed === 1, `suppressed=${_e2.suppressed}`);
check("eagle2: no false-positive on outer_exec (word boundary)", !_e2.findings.some((f: any) => f.sink.includes("outer_exec(")), "no-outer-exec");
const _cg = _buildCallGraph(_e2Fixture);
check("eagle2: call graph reachable from main", _reachableFrom(_cg, "main").size >= 4, `reachable=${[..._reachableFrom(_cg, "main")].length}`);

// 17c. Phase 4 — Differential security analysis
import { analyzeDifferential } from "../src/differential.ts";
const _diff = analyzeDifferential(
  `<?php\n$id = $_GET["id"];\n$q = $wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id=%d", $id));\n$cmd = $_GET["cmd"];\nif (current_user_can("x")) { system($cmd); }\n`,
  `<?php\n$id = $_GET["id"];\n$q = $wpdb->query("SELECT * FROM t WHERE id=$id");\n$cmd = $_GET["cmd"];\nsystem($cmd);\n$u = $_GET["url"];\nfile_get_contents($u);\n`,
  "php",
  "target.php",
);
check("diff: new vulnerability detected", _diff.summary.new_vulnerabilities >= 2, JSON.stringify(_diff.summary));
check("diff: sanitizer removal detected", _diff.summary.sanitizers_removed >= 1, `sanitizers_removed=${_diff.summary.sanitizers_removed}`);
check("diff: authorization removal detected", _diff.summary.authorizations_removed >= 1, `auth_removed=${_diff.summary.authorizations_removed}`);
check("diff: new source detected", _diff.summary.new_sources >= 1, `new_sources=${_diff.summary.new_sources}`);
check("diff: high-severity changes sorted first", _diff.changes[0]?.severity === "high", `first=${_diff.changes[0]?.severity}`);

// 17d. Differential must honor `language` for non-PHP (regression guard)
const _diffJs = analyzeDifferential(
  "const x = req.query.x;\nres.send(escapeHtml(x));\n",
  "const x = req.query.x;\nres.send(x);\n",
  "javascript",
  "target",
);
check("diff: javascript language-aware (new XSS detected)", _diffJs.summary.new_vulnerabilities >= 1, JSON.stringify(_diffJs.summary));

// 17e. Phase 5 — Framework Intelligence
import { listFrameworks as _listFrameworks, detectFramework as _detectFramework, scanFramework as _scanFramework, frameworkProfile as _frameworkProfile } from "../src/frameworks.ts";
const _fws = _listFrameworks();
check("framework: 7 frameworks listed", _fws.length === 7, `got ${_fws.length}`);
check("framework: laravel detected from PHP controller", _detectFramework("<?php\nclass UserController extends Controller {}\n", "php").framework === "laravel", "laravel");
check("framework: wordpress detected from hooks", _detectFramework("<?php\nadd_action(\"wp_ajax_x\", \"x\"); global $wpdb;\n", "php").framework === "wordpress", "wordpress");
check("framework: express detected from app.get", _detectFramework("const app = express();\napp.get(\"/x\", (req, res) => res.send(req.query.x));\n", "javascript").framework === "express", "express");
check("framework: profile has sinks+sources", (_frameworkProfile("laravel")?.sinks.length ?? 0) > 0 && (_frameworkProfile("laravel")?.sources.length ?? 0) > 0, "laravel profile");
const _fwScan = _scanFramework("<?php\n$data = $request->all();\nUser::create($data);\n", "laravel");
check("framework: scan finds static mass assignment sink", _fwScan.sinks.some((h) => h.pattern === "::create("), JSON.stringify(_fwScan.sinks.map((h) => h.pattern)));

// 17f. Phase 7 — MCP Orchestration (state machine + planner + guidance)
import { STATE_MACHINE, buildPlan as _buildPlan, computeGuidance as _computeGuidance, actionPermitted as _actionPermitted } from "../src/orchestration.ts";
check("orchestration: 10-state machine", STATE_MACHINE.length === 10, `states=${STATE_MACHINE.length}`);
const _plan = _buildPlan(true, "bug-bounty", "select_chain");
check("orchestration: plan has 10 steps", _plan.length === 10, `steps=${_plan.length}`);
check("orchestration: 6 done + 4 pending", _plan.filter((p) => p.status === "done").length === 6 && _plan.filter((p) => p.status === "pending").length === 4, JSON.stringify(_plan.map((p) => p.status)));
const _g = _computeGuidance("select_chain", true);
check("orchestration: guidance recommends strike_verify", _g.recommended_tool === "strike_verify", JSON.stringify(_g));
check("orchestration: guidance exposes §34 fields", "state" in _g && "confidence" in _g && "blocking_reason" in _g && "required_evidence" in _g && "recommended_next_action" in _g && "recommended_tool" in _g, "guidance shape");
check("orchestration: strike_verify gated without scope", _actionPermitted("strike_verify", false, "bug-bounty") === false && _actionPermitted("strike_verify", true, "bug-bounty") === true, "risk gate");

// 17g. Phase 8 — Production hardening (cache / SARIF / release / dependency)
import { withCache, cacheStats, cacheKey, clearCache } from "../src/cache.ts";
import { toSarif, sarifLevel } from "../src/sarif.ts";
import { validateRelease as _validateRelease } from "../src/release.ts";
import { checkDependencies as _checkDependencies } from "../src/dependency.ts";
import { changedSourceFiles, analyzeChangedFiles } from "../src/incremental.ts";
clearCache();
withCache("t8", "abc", () => 1);
withCache("t8", "abc", () => 2);
check("cache: hit on repeat (returns cached value)", withCache("t8", "abc", () => 3) === 1, `hit_ratio=${cacheStats().hit_ratio}`);
check("cache: key includes engine version", cacheKey("t8", "abc").includes(":") && cacheKey("t8", "abc") !== cacheKey("t8", "def"), cacheKey("t8", "abc"));
const _sarif = toSarif([{ ruleId: "CWE-89", level: "error", message: "SQLi", file: "a.php", line: 5 }]);
check("sarif: version 2.1.0 + 1 result", _sarif.version === "2.1.0" && (_sarif.runs as any[])[0].results.length === 1, `version=${_sarif.version}`);
check("sarif: severity mapping", sarifLevel("critical") === "error" && sarifLevel("medium") === "warning" && sarifLevel("low") === "note", "levels");
const _rel = _validateRelease();
check("release: package.json == CHANGELOG (consistent)", _rel.consistent === true, JSON.stringify(_rel.checks));
const _dep = _checkDependencies();
check("dependency: no install scripts / git deps", _dep.safe === true, JSON.stringify(_dep));
check("incremental: changedSourceFiles returns a list (empty on bad range)", Array.isArray(changedSourceFiles(".", "HEAD~99", "HEAD")), "changed files");
const _incr = analyzeChangedFiles(".", "HEAD", "HEAD");
check("incremental: analyzeChangedFiles returns shape on empty diff", Array.isArray(_incr.changed_files) && Array.isArray(_incr.findings) && _incr.findings.length === 0, JSON.stringify({ files: _incr.changed_files.length, findings: _incr.findings.length }));

// 17h. Autonomous no-babysitting (inline report + scope classification)
import { runEngagement as _runEngagement, scopeCheck as _scopeCheck } from "../src/orchestrator.ts";
const _scEmpty = _scopeCheck("https://example.com", "", "bug-bounty");
check("scope: classification is recorded (not a gate) — no engagement blocks on it", typeof _scEmpty.allowed === "boolean" && typeof _scEmpty.reason === "string", JSON.stringify(_scEmpty));
const _engReport = _runEngagement("test/fixtures/eagle2-target", "", "bug-bounty", 50, false) as any;
check("autonomous: source audit returns inline report (md+json+sarif+summary)", Boolean(_engReport.report && _engReport.report.markdown && _engReport.report.json && _engReport.report.sarif && _engReport.report.summary), JSON.stringify(Object.keys(_engReport.report ?? {})));


// 17t. Enterprise benchmark — realistic framework-style fixtures
import { runEnterpriseBenchmark as _runEntBench } from "../src/enterprise-benchmark.ts";
const _ent = await _runEntBench();
const _es = _ent.summary as { detected_vulns: number; expected_vulns: number; recall: number };
check("enterprise: 15/15 framework vulns detected (direct detection)", _es.detected_vulns === 15 && _es.expected_vulns === 15 && _es.recall === 1 && true, JSON.stringify(_es));

// 17u. Route-confusion / dispatch-abuse detection
import { detectRouteConfusion as _detectRC } from "../src/route-confusion.ts";
const _rcBatch = _detectRC('<?php\nforeach ($requests as $sub) {\n  $route = $sub["route"];\n  $handler = resolve_route($route);\n  $handler($sub);\n}\n', "batch.php");
const _rcDisp = _detectRC('<?php\n$c = $_GET["c"];\ncall_user_func($c);\n', "d.php");
const _rcMeth = _detectRC('<?php\n$m = $_GET["m"];\n$obj->$m();\n', "m.php");
const _rcInc = _detectRC('<?php\n$p = $_GET["p"];\ninclude($p);\n', "i.php");
check("route-confusion: batch_forwarding + dynamic_dispatch + dynamic_method + dynamic_include", _rcBatch.some((f) => f.type === "batch_forwarding") && _rcDisp.some((f) => f.type === "dynamic_dispatch") && _rcMeth.some((f) => f.type === "dynamic_method_call") && _rcInc.some((f) => f.type === "dynamic_include"), `batch=${_rcBatch.length} disp=${_rcDisp.length} meth=${_rcMeth.length} inc=${_rcInc.length}`);

// 17v. Complex-bug detection (deserialization POP chain / type juggling / mass assignment)
import { detectComplexBugs as _detectCB } from "../src/complex-bugs.ts";
const _cbDeser = _detectCB('<?php\n$d = $_POST["d"];\n$o = unserialize($d);\nclass X { function __destruct() { system("id"); } }\n', "x.php");
const _cbJug = _detectCB('<?php\n$t = $_GET["t"];\nif ($t == $secret) { echo "ok"; }\n', "j.php");
const _cbJugStrict = _detectCB('<?php\n$t = $_GET["t"];\nif ($t === $secret) { echo "ok"; }\n', "s.php");
const _cbMass = _detectCB('<?php\nextract($_REQUEST);\n', "m.php");
check("complex-bugs: deserialization(POP) + type_juggling + strict-safe + mass_assignment", _cbDeser.some((f) => f.type === "deserialization") && _cbJug.some((f) => f.type === "type_juggling") && _cbJugStrict.length === 0 && _cbMass.some((f) => f.type === "mass_assignment"), `deser=${_cbDeser.length} jug=${_cbJug.length} strict=${_cbJugStrict.length} mass=${_cbMass.length}`);

// 17w. Complex-bug detection — prototype pollution / CRLF / path confusion
const _cbProto = _detectCB("const o = {};\nObject.assign(o, req.body);\n", "p.js");
const _cbProtoSafe = _detectCB("const o = {};\nObject.assign(o, { a: 1 });\n", "ps.js");
const _cbCrlf = _detectCB('<?php\nheader("Location: " . $_GET["url"]);\n', "c.php");
const _cbPath = _detectCB('<?php\n$f = $_GET["f"];\necho file_get_contents($f);\n', "pf.php");
const _cbPathSafe = _detectCB('<?php\n$f = basename($_GET["f"]);\necho file_get_contents($f);\n', "pfs.php");
check("complex-bugs: prototype_pollution + crlf + path_confusion (safe suppressed)", _cbProto.some((f) => f.type === "prototype_pollution") && _cbProtoSafe.length === 0 && _cbCrlf.some((f) => f.type === "crlf_injection") && _cbPath.some((f) => f.type === "path_confusion") && _cbPathSafe.length === 0, `proto=${_cbProto.length} protoSafe=${_cbProtoSafe.length} crlf=${_cbCrlf.length} path=${_cbPath.length} pathSafe=${_cbPathSafe.length}`);

// 18. UNIVERSAL multi-language taint engine (PHP/JS/Python/Java)
import { analyzeTaintUniversal, listLanguages as _listLanguages } from "../src/universal-taint.ts";
import "../src/adapters.ts";
check("universal registers 4 languages", _listLanguages().length >= 4, _listLanguages().map((l: any) => l.language).join(","));
const uphp = analyzeTaintUniversal(`<?php $id = $_GET["id"]; $wpdb->query("SELECT * FROM t WHERE id=$id");`, "a.php");
check("universal php sql injection", uphp.findings.length === 1 && uphp.findings[0].sink === "sql_execution", `f=${uphp.findings.length}`);
const ujs = analyzeTaintUniversal(`const id = req.query.id; db.query("SELECT * FROM t WHERE id=" + id);`, "a.js");
check("universal js sql injection", ujs.findings.length === 1 && ujs.findings[0].sink === "sql_execution", `f=${ujs.findings.length}`);
const upy = analyzeTaintUniversal(`import os\nx = request.args.get("id")\nos.system(x)`, "a.py");
check("universal python command injection", upy.findings.length === 1 && upy.findings[0].sink === "command_execution", `f=${upy.findings.length}`);
const ujava = analyzeTaintUniversal(`class A { void f() { String id = request.getParameter("id"); Runtime.getRuntime().exec(id); } }`, "A.java");
check("universal java command injection", ujava.findings.length === 1 && ujava.findings[0].sink === "command_execution", `f=${ujava.findings.length}`);
const ujsSan = analyzeTaintUniversal(`const x = req.query.x; res.send(escapeHtml(x));`, "b.js");
check("universal js sanitizer suppresses", ujsSan.findings.length === 0 && ujsSan.suppressed >= 1, `f=${ujsSan.findings.length} s=${ujsSan.suppressed}`);

// 19. Agent guidance (dynamic next-step directives)
import { nextSteps as _nextSteps } from "../src/guidance.ts";
const gSql = _nextSteps({ tier: "eagle-eye", hasFindings: true, taintedSinks: ["sql_execution"] });
check("guidance sql injection next step", gSql.some((s) => /strike_verify/i.test(s)), gSql.join(" | "));
const gSan = _nextSteps({ tier: "eagle-eye", hasFindings: false, sanitizedCount: 3 });
check("guidance sanitized not-a-finding", gSan.some((s) => /NOT findings/i.test(s)), gSan.join(" | "));
const gLife = _nextSteps({ tier: "strike", findingStatus: "hypothesis" });
check("guidance lifecycle hypothesis -> validating", gLife.some((s) => /validating/i.test(s)), gLife.join(" | "));
const gSsti = _nextSteps({ tier: "eagle-eye", hasFindings: true, taintedSinks: ["template_injection", "xpath_injection", "ldap_injection"] });
check("guidance covers new sink classes (ssti/xpath/ldap)", gSsti.some((s) => /template-expression|SSTI/i.test(s)) && gSsti.some((s) => /XPath/i.test(s)) && gSsti.some((s) => /LDAP/i.test(s)), gSsti.join(" | "));

// 19b. engagement banner + live progress snapshot (orchestrator "in control")
import { engagementBanner as _banner, formatStatus as _fstatus, formatPlanChecklist as _fplan } from "../src/orchestrator.ts";
const _bn = _banner("bench/x", "source");
check("banner announces orchestrator in control", _bn.includes("orchestrator in control") && _bn.includes("scope → recon → analyze → verify → review → report"), _bn.replace(/\n/g, " | "));
const _st = _fstatus({ phase: "analyze", findings: { detected: 4, confirmed: 1 } });
check("formatStatus renders stage index + finding counts", _st.includes("analyze (3/6)") && _st.includes("4 detected") && _st.includes("analyze ▶"), _st.replace(/\n/g, " | "));
const _pl = _fplan([{ order: 1, state: "scope_check", status: "done" }, { order: 2, state: "validate", status: "pending" }]);
check("formatPlanChecklist marks done/pending", _pl.includes("[✓] scope_check") && _pl.includes("[☐] validate"), _pl.replace(/\n/g, " | "));

// 19c. target routing (URL vs source, scheme-less domains)
import { classifyTarget as _cls } from "../src/orchestrator.ts";
const _r1 = _cls("example.com"), _r2 = _cls("192.168.1.1"), _r3 = _cls("myfile.php"), _r4 = _cls("example.com:8080");
check("classifyTarget: bare domain/IP -> live + https", _r1.kind === "live" && _r1.target === "https://example.com" && _r2.kind === "live" && _r2.target === "https://192.168.1.1", `${_r1.target}, ${_r2.target}`);
check("classifyTarget: code filename -> source, host:port -> live", _r3.kind === "source" && _r4.kind === "live" && _r4.target === "https://example.com:8080", `${_r3.kind}, ${_r4.target}`);

// 19d. bypass techniques lookup (WAF/filter/auth/rate-limit)
import { bypassLookup as _bl } from "../src/intel.ts";
const _blList = _bl(), _blWaf = _bl("waf"), _blAuth = _bl("403");
check("bypassLookup: lists 4 categories", _blList.found === true && Array.isArray(_blList.categories) && (_blList.categories as unknown[]).length === 4, JSON.stringify(_blList.categories));
check("bypassLookup: waf + 403 alias resolve", _blWaf.found === true && Array.isArray(_blWaf.techniques) && _blWaf.techniques.length > 0 && _blAuth.found === true && String(_blAuth.defense).toLowerCase().includes("auth"), `${_blWaf.defense} | ${_blAuth.defense}`);

// 19e. chain-to-chain composition + attack vector focus
import { chainLinks as _cl, attackVectors as _av } from "../src/intel.ts";
const _clLinks = _cl(), _avRce = _av("remote_code_execution");
check("chainLinks: returns composition links", _clLinks.found === true && Array.isArray(_clLinks.links) && (_clLinks.links as unknown[]).length >= 10, String(_clLinks.total));
check("attackVectors: includes focus + vectors", _avRce.found === true && typeof _avRce.focus === "string" && _avRce.focus.length > 0 && Array.isArray(_avRce.vectors) && (_avRce.vectors as unknown[]).length > 0, String(_avRce.focus).slice(0, 40));

// 19f. retry guidance (structured failure recovery)
import { retryGuidance as _rg } from "../src/intel.ts";
const _rgList = _rg(), _rgEmpty = _rg("empty output"), _rgRate = _rg("rate limit");
check("retryGuidance: lists 7 modes", _rgList.found === true && Array.isArray(_rgList.modes) && (_rgList.modes as unknown[]).length === 7, String((_rgList.modes as unknown[])?.length));
check("retryGuidance: empty output + rate-limit alias resolve", _rgEmpty.found === true && _rgEmpty.mode === "empty_output" && Array.isArray(_rgEmpty.actions) && (_rgEmpty.actions as unknown[]).length > 0 && _rgRate.found === true && _rgRate.mode === "model_failed", `${_rgEmpty.mode} | ${_rgRate.mode}`);

// 19g. orchestration framework
import { orchestration as _orch } from "../src/intel.ts";
const _orchAll = _orch(), _orchLc = _orch("lifecycle"), _orchT = _orch("termination");
check("orchestration: 6 phases + 4 roles", _orchAll.found === true && Array.isArray(_orchAll.phases) && (_orchAll.phases as unknown[]).length === 6 && Array.isArray(_orchAll.team) && (_orchAll.team as unknown[]).length === 4, `${(_orchAll.phases as unknown[])?.length}p/${(_orchAll.team as unknown[])?.length}r`);
check("orchestration: lifecycle + termination resolve", _orchLc.found === true && Array.isArray(_orchLc.lifecycle) && (_orchLc.lifecycle as unknown[]).length === 6 && _orchT.found === true && Array.isArray((_orchT.termination as { done_when?: unknown[] })?.done_when), `${(_orchLc.lifecycle as unknown[])?.length} | ${(_orchT.termination as { done_when?: unknown[] })?.done_when?.length}`);

// 19i. model fallback (classify + decide recovery)
import { modelFallback as _mf } from "../src/intel.ts";
const _mfList = _mf(), _mfRate = _mf("429 rate limit exceeded"), _mfQuota = _mf("insufficient credits");
check("modelFallback: lists 10 classes + chain", _mfList.found === true && Array.isArray(_mfList.error_classes) && (_mfList.error_classes as unknown[]).length === 10 && Array.isArray(_mfList.fallback_chain), `${(_mfList.error_classes as unknown[])?.length} classes`);
check("modelFallback: rate-limit retryable+backoff, quota non-retryable", _mfRate.found === true && _mfRate.class === "rate_limit" && _mfRate.retryable === true && _mfRate.backoff === true && _mfQuota.found === true && _mfQuota.class === "quota_exceeded" && _mfQuota.retryable === false, `${_mfRate.class}:${_mfRate.retryable} | ${_mfQuota.class}:${_mfQuota.retryable}`);

// 19j. doctrine map (interconnected)
import { doctrineMap as _dm } from "../src/intel.ts";
const _dmAll = _dm(), _dmRecon = _dm("recon"), _dmCross = _dm("cross_cutting");
check("doctrineMap: 6 phases + cross_cutting", _dmAll.found === true && Array.isArray(_dmAll.phases) && (_dmAll.phases as unknown[]).length === 6 && Array.isArray(_dmAll.cross_cutting), `${(_dmAll.phases as unknown[])?.length}p/${(_dmAll.cross_cutting as unknown[])?.length}c`);
check("doctrineMap: recon maps to WSTG-INFO + cross_cutting resolves", _dmRecon.found === true && _dmRecon.wstg === "WSTG-INFO" && Array.isArray(_dmRecon.tools) && (_dmRecon.tools as unknown[]).length > 0 && _dmCross.found === true && Array.isArray(_dmCross.cross_cutting), `${_dmRecon.wstg} | ${(_dmCross.cross_cutting as unknown[])?.length}`);

// 19k. WSTG map (OWASP category -> Blitz coverage)
import { wstgMap as _wm } from "../src/intel.ts";
const _wmAll = _wm(), _wmInpv = _wm("WSTG-INPV"), _wmName = _wm("business logic");
check("wstgMap: 12 categories + WSTG-INPV maps to taint/complex", _wmAll.found === true && Array.isArray(_wmAll.categories) && (_wmAll.categories as unknown[]).length === 12 && _wmInpv.found === true && String(_wmInpv.wstg) === "WSTG-INPV" && Array.isArray(_wmInpv.tools) && (_wmInpv.tools as unknown[]).length > 0, `${(_wmAll.categories as unknown[])?.length}c`);
check("wstgMap: name lookup + advanced tests present", _wmName.found === true && String(_wmName.wstg) === "WSTG-BUSL" && Array.isArray(_wmInpv.advanced) && (_wmInpv.advanced as unknown[]).length > 5, `${_wmName.wstg} | ${(_wmInpv.advanced as unknown[])?.length} advanced`);

// 19l. technique base (detailed per-class methodology)
import { techniqueLookup as _tl } from "../src/intel.ts";
const _tlAll = _tl(), _tlSsti = _tl("ssti"), _tlName = _tl("request smuggling");
check("techniqueLookup: 52 classes + ssti resolves with verify", _tlAll.found === true && Array.isArray(_tlAll.classes) && (_tlAll.classes as unknown[]).length === 52 && _tlSsti.found === true && Array.isArray(_tlSsti.how_to_test) && (_tlSsti.how_to_test as unknown[]).length >= 3 && typeof _tlSsti.verify === "string", `${(_tlAll.classes as unknown[])?.length}c`);
check("techniqueLookup: name lookup resolves to request_smuggling", _tlName.found === true && String(_tlName.id) === "request_smuggling" && Array.isArray(_tlName.techniques), `${_tlName.id}`);

// 19m. framework tricks (framework-specific exploitation)
import { frameworkTricks as _ft } from "../src/intel.ts";
const _ftAll = _ft(), _ftLaravel = _ft("laravel");
check("frameworkTricks: 16 frameworks + laravel has tricks", _ftAll.found === true && Array.isArray(_ftAll.frameworks) && (_ftAll.frameworks as unknown[]).length === 16 && _ftLaravel.found === true && Array.isArray(_ftLaravel.tricks) && (_ftLaravel.tricks as unknown[]).length > 0 && Array.isArray(_ftLaravel.vulns), `${(_ftAll.frameworks as unknown[])?.length}fw | ${_ftLaravel.framework}`);

// 19n. resource index (curated Awesome lists)
import { resourceLookup as _rl } from "../src/intel.ts";
const _rlAll = _rl(), _rlWeb = _rl("web"), _rlKeyword = _rl("privesc");
check("resourceLookup: 78 curated resources (all domains) + web matches", _rlAll.found === true && Array.isArray(_rlAll.resources) && (_rlAll.resources as unknown[]).length >= 78 && _rlWeb.found === true && Array.isArray(_rlWeb.matches) && (_rlWeb.matches as unknown[]).length >= 2, `${(_rlAll.resources as unknown[])?.length}r/${(_rlWeb.matches as unknown[])?.length}w`);
check("resourceLookup: keyword (privesc) resolves to GTFOBins", _rlKeyword.found === true && Array.isArray(_rlKeyword.matches) && (_rlKeyword.matches as unknown[]).some((m: any) => String(m.id) === "gtfobins"), `${(_rlKeyword.matches as unknown[])?.length}`);

// 19o. taxonomy (OWASP API Top 10 + CWE)
import { taxonomy as _tx } from "../src/intel.ts";
const _txApi = _tx("api"), _txApi1 = _tx("api", "API1"), _txCwe = _tx("cwe", "ssrf");
check("taxonomy: 10 API risks + API1 resolves", _txApi.found === true && Array.isArray(_txApi.risks) && (_txApi.risks as unknown[]).length === 10 && _txApi1.found === true && String(_txApi1.name).includes("BOLA"), `${(_txApi.risks as unknown[])?.length}r`);
check("taxonomy: cwe maps ssrf -> CWE-918", _txCwe.found === true && Array.isArray(_txCwe.matches) && (_txCwe.matches as unknown[]).some((m: any) => String(m.cwe) === "CWE-918"), JSON.stringify((_txCwe.matches as unknown[])?.map((m: any) => m.cwe)));
const _txWeb = _tx("web"), _txAsvs = _tx("asvs");
check("taxonomy: 10 OWASP web risks + 14 ASVS chapters", _txWeb.found === true && Array.isArray(_txWeb.risks) && (_txWeb.risks as unknown[]).length === 10 && _txAsvs.found === true && Array.isArray(_txAsvs.chapters) && (_txAsvs.chapters as unknown[]).length === 14, `${(_txWeb.risks as unknown[])?.length}w/${(_txAsvs.chapters as unknown[])?.length}a`);

// 19h. engagement state (deterministic orchestration bookkeeping)
import { startEngagement, setPhase, trackHypothesis, engagementStatus } from "../src/engagement.ts";
const _engStart = startEngagement("/tmp/x", "source");
check("engagement: starts in scope phase", _engStart.started === true && _engStart.phase === "scope", String(_engStart.phase));
const _engEarly = engagementStatus();
check("engagement: not done before report + no hypotheses", (_engEarly.termination as { done?: boolean })?.done === false, JSON.stringify((_engEarly.termination as { unmet?: string[] })?.unmet));
setPhase("verify");
trackHypothesis("sink-a", "pending");
trackHypothesis("sink-b", "confirmed");
const _engMid = engagementStatus();
check("engagement: pending hypothesis blocks termination", (_engMid.termination as { done?: boolean })?.done === false && (_engMid.counts as { pending?: number })?.pending === 1, `${(_engMid.counts as { pending?: number })?.pending}p/${(_engMid.counts as { confirmed?: number })?.confirmed}c`);
setPhase("report");
trackHypothesis("sink-a", "rejected");
const _engDone = engagementStatus();
check("engagement: done when report + no pending", (_engDone.termination as { done?: boolean })?.done === true, JSON.stringify((_engDone.termination as { unmet?: string[] })?.unmet));

// 20. Live recon (pure functions — no network)
import { extractVersion, extractParams, crawlLinks, subdomainEnum as _subEnum } from "../src/live-recon.ts";
const ver = extractVersion({ server: "nginx/1.24.0", "x-powered-by": "PHP/8.1.2" }, `<meta name="generator" content="WordPress 6.4.1" />`);
check("live-recon extracts nginx version", ver.some((v) => v.product === "nginx" && v.version === "1.24.0"), JSON.stringify(ver));
check("live-recon extracts php version", ver.some((v) => v.product === "php" && v.version === "8.1.2"), JSON.stringify(ver));
check("live-recon extracts wordpress version", ver.some((v) => v.product === "wordpress" && v.version === "6.4.1"), JSON.stringify(ver));
const params = extractParams(["https://x.com/search?q=test&page=2", "https://x.com/item?id=42"]);
check("live-recon extracts params", params.includes("q") && params.includes("page") && params.includes("id"), params.join(","));
const { links, scripts } = crawlLinks("https://x.com", `<a href="/about">About</a><a href="/search">Search</a><script src="/app.js"></script>`);
check("live-recon crawls links", links.includes("https://x.com/about") && links.includes("https://x.com/search"), links.join(","));
check("live-recon crawls scripts", scripts.includes("https://x.com/app.js"), scripts.join(","));

// 21. STRIKE validation engine (Phase 3) — verdict resolution end-to-end
import { resolveFinding, type StrikeVerdict as _StrikeVerdict } from "../src/strike.ts";
const _hyp = transition(transition(makeFinding({ title: "Reflected XSS", target: { type: "web", host: "x.com" }, severity: "high", source: { type: "request_parameter", name: "q" }, sink: { type: "html_render" } }), "triaged"), "hypothesis");
const _vConfirmed: _StrikeVerdict = { status: "confirmed", marker_reflected: true, control_reflected: false, baseline: { status: 200, body_preview: "", body_hash: "b" }, marker_response: { status: 200, body_preview: "", body_hash: "m" }, control_response: { status: 200, body_preview: "", body_hash: "c" }, reason: "r", evidence: [{ type: "validation_result", description: "ok", artifacts: [{ name: "m", kind: "http_response", content: "reflected" }] }] };
const _rConfirmed = resolveFinding(_hyp, _vConfirmed);
check("strike confirmed -> status confirmed + evidence", _rConfirmed.status === "confirmed" && _rConfirmed.confidence === 1 && _rConfirmed.evidence.length === 1, `status=${_rConfirmed.status} conf=${_rConfirmed.confidence} ev=${_rConfirmed.evidence.length}`);
const _vFP: _StrikeVerdict = { status: "false_positive", marker_reflected: true, control_reflected: true, baseline: { status: 200, body_preview: "", body_hash: "b" }, marker_response: { status: 200, body_preview: "", body_hash: "m" }, control_response: { status: 200, body_preview: "", body_hash: "c" }, reason: "both reflected", evidence: [] };
const _rFP = resolveFinding(_hyp, _vFP);
check("strike false_positive -> status false_positive", _rFP.status === "false_positive", `status=${_rFP.status}`);
const _vUnconf: _StrikeVerdict = { status: "unconfirmed", marker_reflected: false, control_reflected: false, baseline: { status: 200, body_preview: "", body_hash: "b" }, marker_response: { status: 200, body_preview: "", body_hash: "m" }, control_response: { status: 200, body_preview: "", body_hash: "c" }, reason: "not reflected", evidence: [] };
const _rUnconf = resolveFinding(_hyp, _vUnconf);
check("strike unconfirmed -> stays validating + validation.unconfirmed", _rUnconf.status === "validating" && _rUnconf.validation.status === "unconfirmed", `status=${_rUnconf.status} val=${_rUnconf.validation.status}`);

// 22. Phase 4 — CVSS calculator (verified against known NVD values)
import { cvssAssess, cvssBaseScore, parseCvssVector, cvssSeverity } from "../src/cvss.ts";
check("cvss Log4Shell = 10.0 critical", cvssAssess({ AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H" }).score === 10, "log4shell");
check("cvss SQLi = 9.8", cvssAssess({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" }).score === 9.8, "sqli");
check("cvss severity bands", cvssSeverity(0) === "none" && cvssSeverity(3.9) === "low" && cvssSeverity(6.9) === "medium" && cvssSeverity(8.9) === "high" && cvssSeverity(9.0) === "critical", "bands");
const _cvssParsed = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
check("cvss parse round-trip = 9.8", cvssBaseScore(_cvssParsed!) === 9.8, "parse");

// 23. Phase 4 — dedup + report
import { dedupFindings, rootCauseSignature } from "../src/dedup.ts";
import { reportMarkdown, reportJson } from "../src/report.ts";
const _f1 = makeFinding({ title: "SQLi A", target: { type: "web", host: "a.com" }, severity: "high", cwe: "CWE-89", source: { type: "request_parameter", name: "id" }, sink: { type: "sql_execution" } });
const _f2 = makeFinding({ title: "SQLi B", target: { type: "web", host: "b.com" }, severity: "high", cwe: "CWE-89", source: { type: "request_parameter", name: "id" }, sink: { type: "sql_execution" } });
const _f3 = makeFinding({ title: "XSS", target: { type: "web", host: "c.com" }, severity: "medium", cwe: "CWE-79", source: { type: "request_parameter", name: "q" }, sink: { type: "html_render" } });
const _groups = dedupFindings([_f1, _f2, _f3]);
check("dedup: 3 findings -> 2 root causes", _groups.length === 2 && _groups[0].count === 2, `groups=${_groups.length}`);
check("dedup signature stable", rootCauseSignature(_f1) === rootCauseSignature(_f2), "sig");
const _md = reportMarkdown([_f1], { title: "T" });
check("report markdown has summary", _md.includes("## Summary") && _md.includes(_f1.id), "md");
// reduced finding (no status/confidence fields) must not render "undefined"
const _bare = { title: "No status", classification: { severity: "high", cwe: "CWE-89" }, source: { type: "request_parameter", name: "x" }, sink: { type: "sql_execution", symbol: "DB::select(" } } as never;
const _bareMd = reportMarkdown([_bare], { title: "T" });
check("report defaults missing status/confidence (no 'undefined')", !_bareMd.includes("undefined") && _bareMd.includes("detected") && _bareMd.includes("unscored"), _bareMd.split("\n").filter((l) => l.includes("Status") || l.includes("Confidence")).join(" | "));
const _js = reportJson([_f1], { title: "T" });
check("report json has integrity hash", _js.includes("integrity"), "json");

// 24. Phase 4 — benchmark + coverage
import { runBenchmark, loadCorpus } from "../src/benchmark.ts";
import { coverageMatrix } from "../src/coverage.ts";
const _bench = runBenchmark() as any;
check("benchmark: 0 fp 0 fn on 100+ fixture corpus", _bench.fp === 0 && _bench.fn === 0 && _bench.total_cases >= 100 && _bench.detection_rate === 1, `tp=${_bench.tp} tn=${_bench.tn} fp=${_bench.fp} fn=${_bench.fn} total=${_bench.total_cases}`);
const _cov = coverageMatrix();
check("coverage matrix has 4 languages", _cov.counts.languages === 4, `langs=${_cov.counts.languages}`);
check("coverage matrix tracks 7 frameworks", _cov.counts.frameworks === 7, `frameworks=${_cov.counts.frameworks}`);
check("coverage ratio in (0,1]", _cov.coverage_ratio > 0 && _cov.coverage_ratio <= 1, `ratio=${_cov.coverage_ratio}`);
const _covBySink = Object.fromEntries(_cov.sink_coverage.map((s) => [s.sink, s.languages]));
check("coverage: xxe + zip-slip now covered (all 4 langs)", _covBySink.xml_processing?.length === 4 && _covBySink.archive_extraction?.length === 4, `xml=${_covBySink.xml_processing?.length} zip=${_covBySink.archive_extraction?.length}`);
check("coverage: 3 new classes (ssti/xpath/ldap) present", ["template_injection", "xpath_injection", "ldap_injection"].every((s) => _covBySink[s]?.length === 4), `ssti=${_covBySink.template_injection?.length} xpath=${_covBySink.xpath_injection?.length} ldap=${_covBySink.ldap_injection?.length}`);

console.log();
const nPass = results.filter(([, ok]) => ok).length;
console.log(`=== ${nPass}/${results.length} checks passed ===`);
process.exit(nPass === results.length ? 0 : 1);
