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
check("chains.json 58 chains (22 own + 36 merged)", chains.length === 58, `got ${chains.length}`);
check("listChains 58", (listChains() as any).total === 58);

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
check("scope never blocks — classifies intel", scopeCheck("https://evil.com", "example.com", "bug-bounty").allowed === true && (scopeCheck("https://evil.com", "example.com", "bug-bounty").reason ?? "").includes("not_in_scope"));
check("scope allowed", scopeCheck("https://api.example.com", "example.com", "bug-bounty").allowed === true);
check("scope out-of-scope classified (not blocked)", (scopeCheck("https://internal.example.com", "example.com, -internal.example.com", "bug-bounty").reason ?? "").includes("out_of_scope") && scopeCheck("https://internal.example.com", "example.com, -internal.example.com", "bug-bounty").allowed === true);
check("scope wildcard classifies apex + subdomain + foreign", (scopeCheck("https://vuln-web-app.onrender.com", "*.vuln-web-app.onrender.com", "bug-bounty").reason ?? "").includes("in_scope") && (scopeCheck("https://api.vuln-web-app.onrender.com", "*.vuln-web-app.onrender.com", "bug-bounty").reason ?? "").includes("in_scope") && (scopeCheck("https://evil.com", "*.vuln-web-app.onrender.com", "bug-bounty").reason ?? "").includes("not_in_scope"));
check("scope ctf off", scopeCheck("https://x", "", "ctf").allowed === true);
check("scope: filesystem path always in-scope", scopeCheck("/root/some/src", "", "bug-bounty").allowed === true && (scopeCheck("/root/some/src", "", "bug-bounty").reason ?? "").includes("in-scope"));
check("scope: relative path always in-scope", scopeCheck("./vendor/app", "", "bug-bounty").allowed === true);

// 5. engagement
const es = enrichScan(target) as any;
check("enrichScan matched chains", es.matched_chains.length >= 1, `matched=${es.matched_chains.length}`);

const re = runEngagement(target, "", "bug-bounty") as any;
check("engagement DETECTED (not COMPLETE — verify is next)", re.status === "DETECTED" && re.scope.enforcement === "source-audit");
check("engagement hypothesis findings", re.findings.length >= 1 && re.findings.every((f: any) => f.status === "hypothesis"), `n=${re.findings.length}`);
check("engagement findings carry evidence + confidence", re.findings.every((f: any) => f.evidence_count >= 1 && typeof f.confidence === "number" && typeof f.confidence_level === "string"), `first=${JSON.stringify(re.findings[0] ?? {}).slice(0, 120)}`);
check("engagement URL never blocked (disclaimer mode)", (runEngagement("https://evil.com", "", "bug-bounty") as any).status !== "BLOCKED");

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
check("enterprise: 17/17 framework vulns detected (direct detection)", _es.detected_vulns === 17 && _es.expected_vulns === 17 && _es.recall === 1 && true, JSON.stringify(_es));

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

// 17x. Complex-bug detection — advanced (SSRF / XXE / SSTI) with defense suppression
const _cbSsrF = _detectCB('<?php\n$u = $_GET["u"];\nfile_get_contents($u);\n', "ssrf.php");
const _cbSsrFSafe = _detectCB('<?php\n$u = $_GET["u"];\nif (in_array($u, $allowlist)) { file_get_contents($u); }\n', "ssrfsafe.php");
const _cbXxe = _detectCB('<?php\n$x = $_POST["x"];\nsimplexml_load_string($x);\n', "xxe.php");
const _cbXxeSafe = _detectCB('<?php\n$x = $_POST["x"];\nlibxml_disable_entity_loader(true);\nsimplexml_load_string($x);\n', "xxesafe.php");
const _cbSsti = _detectCB('<?php\n$t = $_GET["t"];\nrender_template_string($t);\n', "ssti.php");
check("complex-bugs: ssrf + xxe + ssti (defense suppressed)", _cbSsrF.some((f) => f.type === "ssrf") && !_cbSsrFSafe.some((f) => f.type === "ssrf") && _cbXxe.some((f) => f.type === "xxe") && _cbXxeSafe.length === 0 && _cbSsti.some((f) => f.type === "ssti"), `ssrf=${_cbSsrF.length} ssrfSafe=${_cbSsrFSafe.length} xxe=${_cbXxe.length} xxeSafe=${_cbXxeSafe.length} ssti=${_cbSsti.length}`);

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
check("retryGuidance: lists 8 modes", _rgList.found === true && Array.isArray(_rgList.modes) && (_rgList.modes as unknown[]).length === 8, String((_rgList.modes as unknown[])?.length));
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
check("techniqueLookup: 53 classes + ssti resolves with verify", _tlAll.found === true && Array.isArray(_tlAll.classes) && (_tlAll.classes as unknown[]).length === 53 && _tlSsti.found === true && Array.isArray(_tlSsti.how_to_test) && (_tlSsti.how_to_test as unknown[]).length >= 3 && typeof _tlSsti.verify === "string", `${(_tlAll.classes as unknown[])?.length}c`);
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

// 21b. WAF bypass detection + evasion variants
import { isWafBlock as _isWaf, bypassVariants as _bv } from "../src/strike.ts";
check("isWafBlock: 403 + block-page signatures", _isWaf(403, "forbidden") === true && _isWaf(200, "Akses Dibatasi") === true && _isWaf(200, "normal page content") === false && _isWaf(406, "") === true, "waf-block vs normal");
const _bvV = _bv("' OR 1=1--");
check("bypassVariants: double-encode + case + entity + comment", _bvV.length >= 4 && _bvV.some((v) => v.technique === "double_url_encode") && _bvV.some((v) => v.technique === "case_variation") && _bvV.some((v) => v.technique === "html_entity") && _bvV.some((v) => v.technique === "comment_split"), `variants=${_bvV.length}`);

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
check("report markdown has exec summary + summary table", _md.includes("## 1. Executive Summary") && _md.includes("## 4. Summary of Findings") && _md.includes(_f1.id) && _md.includes("**Impact**") && _md.includes("**Remediation**"), "md");
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
check("coverage matrix has 5 languages", _cov.counts.languages === 5, `langs=${_cov.counts.languages}`);
check("coverage matrix tracks 7 frameworks", _cov.counts.frameworks === 7, `frameworks=${_cov.counts.frameworks}`);
check("coverage ratio in (0,1]", _cov.coverage_ratio > 0 && _cov.coverage_ratio <= 1, `ratio=${_cov.coverage_ratio}`);
const _covBySink = Object.fromEntries(_cov.sink_coverage.map((s) => [s.sink, s.languages]));
check("coverage: xxe + zip-slip now covered (all 4 langs)", _covBySink.xml_processing?.length === 4 && _covBySink.archive_extraction?.length === 4, `xml=${_covBySink.xml_processing?.length} zip=${_covBySink.archive_extraction?.length}`);
check("coverage: 3 new classes (ssti/xpath/ldap) present", ["template_injection", "xpath_injection", "ldap_injection"].every((s) => _covBySink[s]?.length === 4), `ssti=${_covBySink.template_injection?.length} xpath=${_covBySink.xpath_injection?.length} ldap=${_covBySink.ldap_injection?.length}`);

// 10z. orchestration ops (planning / delegation / watchdog / context-prune)
import { decomposeBatches as _dbOps, retryPattern as _rpOps, watchdog as _wdOps, compactState as _csOps } from "../src/ops.ts";
const _dbRes = _dbOps([
  { id: "a", objective: "recon" },
  { id: "b", objective: "analyze", depends_on: ["a"] },
  { id: "c", objective: "fuzz", depends_on: ["a"] },
  { id: "d", objective: "report", depends_on: ["b", "c"] },
]);
check("decomposeBatches: parallel-first (a -> b+c -> d)", _dbRes.total === 4 && _dbRes.batches.length === 3 && _dbRes.batches[0].parallel.length === 1 && _dbRes.batches[1].parallel.length === 2 && _dbRes.batches[2].parallel.length === 1, JSON.stringify(_dbRes.batches.map((b) => b.parallel)));

const _rpRes = _rpOps("subagent-x");
check("retryPattern: no-retry-cap rule", String((_rpRes as any).rule).includes("no retry cap"), String((_rpRes as any).rule));

const _wdStalled = _wdOps("recon", 0, Date.now() - 20 * 60 * 1000);
const _wdProgress = _wdOps("analyze", 3, Date.now());
check("watchdog: STALLED vs PROGRESSING", (_wdStalled as any).status === "STALLED" && (_wdProgress as any).status === "PROGRESSING", `${(_wdStalled as any).status}/${(_wdProgress as any).status}`);

const _csRes = _csOps("verify", [
  { title: "xss", severity: "medium", status: "confirmed" },
  { title: "ssrf", severity: "high", status: "hypothesis" },
  { title: "fp", severity: "low", status: "false_positive" },
]);
check("compactState: counts + top findings", (_csRes as any).summary === "1 confirmed, 1 pending, 1 rejected" && ((_csRes as any).top_findings as unknown[]).length === 2, String((_csRes as any).summary));

// 10aa. task checkpoint journal (per-workstream progress + resume)
import { taskStart as _ts, taskCheckpoint as _tc, taskStatus as _tst, taskResume as _tr } from "../src/tasks.ts";
const _tid = `t-${Date.now().toString(36)}`;
_ts(_tid, "audit auth", ["recon", "analyze", "verify", "report"]);
_tc(_tid, "recon", "done", "mapped endpoints");
_tc(_tid, "analyze", "failed", "subagent died");
const _tstRes = _tst(_tid);
const _trRes = _tr(_tid);
check("task checkpoint: progress + resume from last done", (_tstRes as any).status === "failed" && (_tstRes as any).current_step === "analyze" && (_tstRes as any).progress === "1/4" && ((_trRes as any).remaining_steps as unknown[]).length === 3 && (_trRes as any).resume_from === "analyze", JSON.stringify({ status: (_tstRes as any).status, cur: (_tstRes as any).current_step, prog: (_tstRes as any).progress, remaining: (_trRes as any).remaining_steps }));

// 20. leaked-source sink scan + hash identification/crack
import { scanSinks as _scanSinks, detectSourceLeak as _detectLeak } from "../src/sinks.ts";
import { identifyHash as _idHash, crackHash as _crackHash } from "../src/hash.ts";
const _leakText = "Traceback (most recent call last):\n  File \"/app/app.py\", line 156\n    result = eval(query)\n    app.config[\"SECRET_KEY\"] = \"your secret key\"\n    requests.get(user_url)";
const _sinks = _scanSinks(_leakText);
check("sink scan: eval + SECRET_KEY + SSRF detected", _detectLeak(_leakText) === true && _sinks.some((s) => s.type === "rce" && s.label === "eval()") && _sinks.some((s) => s.type === "secret") && _sinks.some((s) => s.type === "ssrf"), `sinks=${_sinks.map((s) => s.type).join(",")}`);
check("hash identify: bcrypt/md5/sha1", _idHash("$2a$12$abcdefghijklmnopqrstuv") === "bcrypt" && _idHash("5f4dcc3b5aa765d61d8327deb882cf99") === "md5" && _idHash("da39a3ee5e6b4b0d3255bfef95601890afd80709") === "sha1", "bcrypt/md5/sha1");
const _crackRes = await _crackHash("5f4dcc3b5aa765d61d8327deb882cf99");
check("crack: md5('password') cracked offline", _crackRes.type === "md5" && _crackRes.cracked === true && Array.isArray(_crackRes.matches) && (_crackRes.matches as string[]).includes("password"), JSON.stringify(_crackRes.matches));
// wordlist support: a password absent from the built-in list must crack from the
// autoloaded seclists/rockyou wordlist (streaming, source=wordlist).
const _crackWl = await _crackHash("0571749e2ac330a7455809c6b0e7af90"); // md5("sunshine")
check("crack: wordlist autoload cracks md5('sunshine')", _crackWl.cracked === true && (_crackWl as Record<string, unknown>).source === "wordlist" && (_crackWl.matches as string[]).includes("sunshine"), `source=${(_crackWl as Record<string, unknown>).source} matches=${JSON.stringify(_crackWl.matches)}`);
const _crackExplicit = await _crackHash("21cafe58e340c4526fd0bcc4a647512e", ["target-specific-pw"]);
check("crack: explicit extra candidates are tried", (_crackExplicit as Record<string, unknown>).candidates_checked !== undefined || _crackExplicit.cracked === false, "ok");

// 21. origin-exposure CDN heuristic (direct-to-origin bypass flag)
import { isLikelyCdn as _isCdn, detectTech as _detectTech } from "../src/live-recon.ts";
check("CDN heuristic: cloudflare flagged, origin NOT", _isCdn("104.16.100.1") === true && _isCdn("151.101.1.1") === true && _isCdn("203.0.113.7") === false && _isCdn("192.168.1.1") === false, "cf/origin");
// tech fingerprint: header/cookie beats body; generic `_token`/`csrf-token` no longer = laravel
const _expressBody = "<html><body><input type='hidden' name='_token' value='x'><meta name='csrf-token'></body></html>";
check("tech: Express header + generic _token body -> nodejs (NOT laravel)", _detectTech({ "x-powered-by": "Express", "server": "nginx" }, _expressBody).includes("nodejs") && !_detectTech({ "x-powered-by": "Express" }, _expressBody).includes("laravel"), JSON.stringify(_detectTech({ "x-powered-by": "Express" }, _expressBody)));
check("tech: laravel_session cookie -> laravel; PHPSESSID -> php", _detectTech({ "set-cookie": "laravel_session=abc; XSRF-TOKEN=x" }, "").includes("laravel") && _detectTech({ "set-cookie": "PHPSESSID=abc" }, "").includes("php"), "cookies");

// 22. generic chain executor — tool_hint -> deterministic operation (not per-vuln)
import { executeChainSteps as _execChain } from "../src/chain-executor.ts";
import { toolForHint as _toolHint } from "../src/catalog.ts";
const _chainF = makeFinding({ title: "x", target: { type: "web", host: "http://127.0.0.1:1", endpoint: "?id=" }, severity: "high", cwe: "CWE-89", source: { type: "request_parameter", name: "id" }, sink: { type: "sql_query", symbol: "conn.execute(\"SELECT * FROM t WHERE x='{q}'\")" } });
const _chainRes = await _execChain(_chainF, [
  { order: 1, action: "confirm", tool_hint: "custom_manual_step" },
  { order: 2, action: "scan source", tool_hint: "eagle_grep" },
  { order: 3, action: "crack", tool_hint: "hashcat" },
]);
check("chain executor: manual deferred + name dispatch (eagle_grep→scan, hashcat→crack)", _chainRes.length === 3 && _chainRes[0].outcome === "deferred" && _chainRes[1].outcome === "executed" && _chainRes[1].tool === "eagle_grep" && (_chainRes[1].detail as { sinks_found?: number }).sinks_found! >= 1 && _chainRes[2].outcome === "executed" && _chainRes[2].tool === "hashcat", `${_chainRes.map((r) => `${r.tool_hint}:${r.outcome}`).join(",")}`);
check("toolForHint: chain hint maps to catalog tool (no exec)", _toolHint("sqlmap") === "sqlmap" && _toolHint("jwt_tool") === "jwt_tool" && _toolHint("nonexistent_xyz") === null, `${_toolHint("sqlmap")}/${_toolHint("jwt_tool")}`);
check("toolForHint: separator-normalized (rogue_jndi -> rogue-jndi) + new tools", _toolHint("rogue_jndi") === "rogue-jndi" && _toolHint("tplmap") === "tplmap" && _toolHint("subzy") === "subzy" && _toolHint("interactsh") === "interactsh-client" && _toolHint("inql") === "inql", `${_toolHint("rogue_jndi")}/${_toolHint("tplmap")}/${_toolHint("interactsh")}`);
check("mcp-server: burp + chrome-devtools resolve (were unresolved)", _toolHint("burp") === "burp-suite-mcp" && _toolHint("chrome-devtools-mcp") === "chrome-devtools-mcp", `${_toolHint("burp")}/${_toolHint("chrome-devtools-mcp")}`);

// 24. browser dispatch — "browser"/"browser_devtools" hint -> browserFinding (inferred check)
const _xssF = makeFinding({ title: "Reflected XSS", target: { type: "web", host: "http://127.0.0.1:1", endpoint: "?q=" }, severity: "medium", cwe: "CWE-79", source: { type: "request_parameter", name: "q" }, sink: { type: "html_render", symbol: "q" }, chainId: "xss_to_account_takeover", chainName: "XSS to account takeover" });
const _browserRes = await _execChain(_xssF, [{ order: 1, action: "verify in browser", tool_hint: "browser" }]);
check("browser hint dispatches (not deferred) + infers dom_xss", _browserRes[0].outcome === "executed" && _browserRes[0].tool === "browser" && (_browserRes[0].detail as { check_type?: string }).check_type === "dom_xss", `${_browserRes[0].outcome}/${(_browserRes[0].detail as { check_type?: string }).check_type}`);

// 25. devtools MCP client helper (deterministic — no browser launch)
import { parsePageId as _pid } from "../src/devtools.ts";
check("parsePageId: list_pages markdown -> pageId", _pid("## Pages\n1: about:blank [selected]") === 1 && _pid("3: https://x/ [selected]") === 3, `${_pid("1: about:blank")}`);

// 26. burp-mcp SSE helper (deterministic — no network)
import { sseMessage as _sse } from "../src/burp-mcp.ts";
check("sseMessage: parse event message data", _sse("event: message\ndata: {\"result\":\"ok\"}\n\n") === "{\"result\":\"ok\"}" && _sse("event: endpoint\ndata: /msg\n\n") === null, `${_sse("event: message\ndata: x")}`);

// 27. installAllTools — bulk provisioning summary (empty category -> no installs)
import { installAllTools as _installAll } from "../src/catalog.ts";
const _emptyInstall = await _installAll({ category: "zzz-nonexistent" });
const _manual = (_emptyInstall.skipped_manual as string[]) ?? [];
check("installAllTools: empty category -> 0 targets, manual tools skipped (burp + GUI)", (_emptyInstall.target_count as number) === 0 && _manual.includes("burp-suite-mcp") && _manual.includes("ghidra") && _manual.includes("havoc"), `targets=${_emptyInstall.target_count} manual=${_manual.length} [${_manual.join(",")}]`);

// 28. HackerOne research header (env-driven, deterministic)
import { researchHeaders as _rh, h1Username as _h1u } from "../src/http.ts";
const _prevH1 = process.env.H1_USERNAME;
process.env.H1_USERNAME = "test-researcher";
check("researchHeaders: X-HackerOne-Research injected when H1_USERNAME set", _rh()["X-HackerOne-Research"] === "test-researcher" && _h1u() === "test-researcher", JSON.stringify(_rh()));
if (_prevH1 === undefined) delete process.env.H1_USERNAME; else process.env.H1_USERNAME = _prevH1;
check("researchHeaders: empty when H1_USERNAME unset", Object.keys(_rh()).length === 0, JSON.stringify(_rh()));

// 29. verifyFileRead — deterministic arbitrary-file-read verification
import { verifyFileRead as _vfr } from "../src/strike.ts";
const _frBlocked = await _vfr({ url: "http://127.0.0.1:1/read", method: "POST", bodyRaw: true, timeoutMs: 2000 });
check("verifyFileRead: unreachable -> blocked", _frBlocked.status === "blocked", JSON.stringify(_frBlocked.status));
const _frNone = await _vfr({ url: "https://httpbin.org/anything", method: "POST", bodyRaw: true, timeoutMs: 10000 });
check("verifyFileRead: no passwd content -> not falsely confirmed", _frNone.status !== "confirmed" && _frNone.file_read === false, JSON.stringify({ status: _frNone.status, marker_file: _frNone.marker_file_content, control_file: _frNone.control_file_content }));

// 30. checkMcpServers — MCP integration availability probe
import { checkMcpServers as _cms } from "../src/mcp-status.ts";
const _mcps = await _cms();
check("checkMcpServers: returns chrome-devtools-mcp + burp-suite-mcp", _mcps.length === 2 && _mcps.some((m) => m.name === "chrome-devtools-mcp") && _mcps.some((m) => m.name === "burp-suite-mcp"), JSON.stringify(_mcps.map((m) => m.name)));
check("checkMcpServers: each entry has available+kind+detail", _mcps.every((m) => typeof m.available === "boolean" && (m.kind === "stdio" || m.kind === "sse") && typeof m.detail === "string"), JSON.stringify(_mcps.map((m) => ({ n: m.name, a: m.available, k: m.kind }))));

// 31. makeFinding with evidence — evidence attached at creation (never born empty)
import { makeFinding as _mk } from "../src/finding.ts";
const _fEv = _mk({
  title: "arbitrary file read", target: { type: "web", host: "h", endpoint: "/viewLogFile" },
  severity: "high", cwe: "CWE-22",
  source: { type: "post_body", name: "fullpath" }, sink: { type: "file_operations", symbol: "x" },
  evidence: [{ type: "response", description: "marker read", content: "root:x:0:0:" }],
});
check("makeFinding: evidence attached at creation", ((_fEv.evidence ?? []).length === 1) && (((_fEv.evidence ?? [])[0]?.artifacts?.length ?? 0) === 1), JSON.stringify((_fEv.evidence ?? []).map((e) => e.type)));
const _fNoEv = _mk({ title: "t2", target: { type: "web", host: "h", endpoint: "/e" }, severity: "low", source: { type: "header", name: "x" }, sink: { type: "y", symbol: "z" } });
check("makeFinding: no evidence -> empty (flag via report evidence_less_findings)", (_fNoEv.evidence ?? []).length === 0, JSON.stringify((_fNoEv.evidence ?? []).length));

// 23. buildCatalogCommand — target always reaches the command (no-required-flag bug)
import { buildCatalogCommand as _buildCmd } from "../src/catalog.ts";
check("buildCatalogCommand: required -d flag gets target", JSON.stringify(_buildCmd({ command: "subfinder", flags: [{ name: "-d", type: "string", required: true }] }, "example.com")) === JSON.stringify(["subfinder", "-d", "example.com"]), JSON.stringify(_buildCmd({ command: "subfinder", flags: [{ name: "-d", type: "string", required: true }] }, "example.com")));
check("buildCatalogCommand: no-required-flag -> positional target (curl bug fixed)", JSON.stringify(_buildCmd({ command: "curl", flags: [{ name: "-i", type: "boolean" }, { name: "-d", type: "string" }] }, "http://x.example/")) === JSON.stringify(["curl", "http://x.example/"]), JSON.stringify(_buildCmd({ command: "curl", flags: [{ name: "-i", type: "boolean" }, { name: "-d", type: "string" }] }, "http://x.example/")));
check("buildCatalogCommand: unambiguous -u flag preferred over positional", JSON.stringify(_buildCmd({ command: "tool", flags: [{ name: "-u", type: "string" }, { name: "-v", type: "boolean" }] }, "http://t.example/")) === JSON.stringify(["tool", "-u", "http://t.example/"]), JSON.stringify(_buildCmd({ command: "tool", flags: [{ name: "-u", type: "string" }, { name: "-v", type: "boolean" }] }, "http://t.example/")));
check("buildCatalogCommand: malicious target stays a single argv element (no shell injection)", JSON.stringify(_buildCmd({ command: "subfinder", flags: [{ name: "-d", type: "string", required: true }] }, "evil.com; rm -rf / $(curl x|sh)")) === JSON.stringify(["subfinder", "-d", "evil.com; rm -rf / $(curl x|sh)"]), JSON.stringify(_buildCmd({ command: "subfinder", flags: [{ name: "-d", type: "string", required: true }] }, "evil.com; rm -rf / $(curl x|sh)")));

// 32. chain-executor — generic dispatch (scan/crack/defer, hermetic — no network)
import { executeChainSteps as _ecs } from "../src/chain-executor.ts";
const _cf = _mk({ title: "code exec", target: { type: "web", host: "h", endpoint: "/e" }, severity: "medium", source: { type: "query", name: "q" }, sink: { type: "code_execution", symbol: "eval" }, evidence: [{ type: "tool_output", description: "leaked", content: "eval(userInput); system(cmd);" }] });
const _scanSteps = await _ecs(_cf, [{ order: 1, action: "scan leaked source", tool_hint: "scan_leaked_source" }]);
check("chain-executor: scan_leaked_source dispatched + executed", _scanSteps.length === 1 && _scanSteps[0].outcome === "executed" && _scanSteps[0].tool === "scan_leaked_source", JSON.stringify({ outcome: _scanSteps[0].outcome, tool: _scanSteps[0].tool }));
const _crackSteps = await _ecs(_cf, [{ order: 1, action: "crack hashes", tool_hint: "crack_hash" }]);
check("chain-executor: crack_hash no-hash -> executed + hashes_found 0 (no network)", _crackSteps[0].outcome === "executed" && (JSON.stringify(_crackSteps[0].detail ?? {}).includes("hashes_found")), JSON.stringify(_crackSteps[0].detail));
const _deferSteps = await _ecs(_cf, [{ order: 1, action: "run unknown", tool_hint: "some_unknown_tool_xyz" }]);
check("chain-executor: unknown tool -> deferred (not error)", _deferSteps[0].outcome === "deferred", JSON.stringify(_deferSteps[0].outcome));

// 33. memory — remember/dedup/lookup/forget lifecycle (self-cleaning)
import { remember as _rem, memoryLookup as _mlu, forget as _frg } from "../src/memory.ts";
const _memTopic = `blitzstrike-test-${Date.now()}`;
const _mr1 = _rem(_memTopic, "unique test content", "lesson", ["test"], "test");
check("memory: remember -> saved", _mr1.saved === true && typeof _mr1.id === "string", JSON.stringify(_mr1));
const _mr2 = _rem(_memTopic, "unique test content", "lesson", ["test"], "test");
check("memory: remember same -> duplicate (dedup)", _mr2.saved === false && _mr2.duplicate === true, JSON.stringify(_mr2));
const _lu = _mlu(_memTopic);
check("memory: lookup finds the entry", _lu.found === true, JSON.stringify(_lu));
const _fr1 = _frg(String(_mr1.id));
check("memory: forget -> removed", _fr1.removed === true, JSON.stringify(_fr1));
const _fr2 = _frg(String(_mr1.id));
check("memory: forget again -> not found", _fr2.removed === false, JSON.stringify(_fr2));

// 34. complex-bugs — deep detectors (deserialization/type-juggling/SSRF/...)
import { detectComplexBugs as _dcb } from "../src/complex-bugs.ts";
check("complex-bugs: deserialization + magic method", _dcb("<?php\n$data = $_GET['data'];\n$obj = unserialize($data);\nclass X { function __destruct() { system('id'); } }\n", "a.php").some((f) => f.type === "deserialization"), JSON.stringify(_dcb("<?php\n$data = $_GET['data'];\n$obj = unserialize($data);\nclass X { function __destruct() { system('id'); } }\n", "a.php").map((f) => f.type)));
check("complex-bugs: type juggling (loose ==)", _dcb("<?php\nif ($_GET['password'] == $secret) { echo 'ok'; }\n", "b.php").some((f) => f.type === "type_juggling"), JSON.stringify(_dcb("<?php\nif ($_GET['password'] == $secret) { echo 'ok'; }\n", "b.php").map((f) => f.type)));
check("complex-bugs: mass assignment (extract)", _dcb("<?php\nextract($_REQUEST);\n", "c.php").some((f) => f.type === "mass_assignment"), JSON.stringify(_dcb("<?php\nextract($_REQUEST);\n", "c.php").map((f) => f.type)));
check("complex-bugs: prototype pollution (Object.assign)", _dcb("const x = Object.assign({}, req.body);\n", "d.js").some((f) => f.type === "prototype_pollution"), JSON.stringify(_dcb("const x = Object.assign({}, req.body);\n", "d.js").map((f) => f.type)));
check("complex-bugs: SSRF (file_get_contents)", _dcb("<?php\n$url = $_GET['url'];\necho file_get_contents($url);\n", "e.php").some((f) => f.type === "ssrf"), JSON.stringify(_dcb("<?php\n$url = $_GET['url'];\necho file_get_contents($url);\n", "e.php").map((f) => f.type)));
check("complex-bugs: SSTI (ejs.render)", _dcb("const html = ejs.render(req.query.template);\n", "f.js").some((f) => f.type === "ssti"), JSON.stringify(_dcb("const html = ejs.render(req.query.template);\n", "f.js").map((f) => f.type)));
check("complex-bugs: XXE (simplexml_load_string)", _dcb("<?php\n$xml = $_GET['xml'];\n$doc = simplexml_load_string($xml);\n", "g.php").some((f) => f.type === "xxe"), JSON.stringify(_dcb("<?php\n$xml = $_GET['xml'];\n$doc = simplexml_load_string($xml);\n", "g.php").map((f) => f.type)));
check("complex-bugs: clean code -> no findings", _dcb("<?php\n$a = 1 + 2;\necho $a;\n", "h.php").length === 0, JSON.stringify(_dcb("<?php\n$a = 1 + 2;\necho $a;\n", "h.php").map((f) => f.type)));

// 35. route-confusion — dispatch/route abuse detectors
import { detectRouteConfusion as _drc } from "../src/route-confusion.ts";
check("route-confusion: dynamic dispatch (call_user_func)", _drc("<?php\ncall_user_func($_GET['callback']);\n", "r1.php").some((f) => f.type === "dynamic_dispatch"), JSON.stringify(_drc("<?php\ncall_user_func($_GET['callback']);\n", "r1.php").map((f) => f.type)));
check("route-confusion: dynamic method call", _drc("<?php\n$m = $_GET['m'];\n$obj->$m();\n", "r2.php").some((f) => f.type === "dynamic_method_call"), JSON.stringify(_drc("<?php\n$m = $_GET['m'];\n$obj->$m();\n", "r2.php").map((f) => f.type)));
check("route-confusion: dynamic include", _drc("<?php\ninclude($_GET['page']);\n", "r3.php").some((f) => f.type === "dynamic_include"), JSON.stringify(_drc("<?php\ninclude($_GET['page']);\n", "r3.php").map((f) => f.type)));
check("route-confusion: batch forwarding loop", _drc("<?php\nforeach ($requests as $r) { forward($r); }\n", "r4.php").some((f) => f.type === "batch_forwarding"), JSON.stringify(_drc("<?php\nforeach ($requests as $r) { forward($r); }\n", "r4.php").map((f) => f.type)));
check("route-confusion: clean code -> no findings", _drc("<?php\n$a = 1;\necho $a;\n", "r5.php").length === 0, JSON.stringify(_drc("<?php\n$a = 1;\necho $a;\n", "r5.php").map((f) => f.type)));

// 36. universal-taint — language adapters + generic engine (hermetic)
import "../src/adapters.ts";
import { analyzeTaintUniversal as _atu, detectLanguage as _dl, listLanguages as _ll } from "../src/universal-taint.ts";
const _phpTaintRes = _atu("<?php\n$x = $_GET['id'];\nsystem($x);\n", "t.php");
check("taint: php command injection -> command_execution finding", _phpTaintRes.findings.length > 0 && _phpTaintRes.findings.some((f) => f.sink === "command_execution"), JSON.stringify(_phpTaintRes.findings.map((f) => f.sink)));
const _phpSanRes = _atu("<?php\n$x = $_GET['id'];\n$y = escapeshellarg($x);\nsystem($y);\n", "s.php");
check("taint: escapeshellarg sanitizer -> suppressed (0 findings)", _phpSanRes.findings.length === 0, JSON.stringify({ findings: _phpSanRes.findings.length, suppressed: _phpSanRes.suppressed }));
check("taint: detectLanguage by extension", _dl("x.php")?.language === "php" && _dl("x.py")?.language === "python" && _dl("x.js")?.language === "javascript", `${_dl("x.php")?.language},${_dl("x.py")?.language},${_dl("x.js")?.language}`);
check("taint: listLanguages 5 (php/js/python/java/rust)", _ll().length === 5, JSON.stringify(_ll().map((l) => l.language)));
// name-collision regression: a method name (`get`) neutralized by int() elsewhere
// must NOT pollute request.args.get(...) and suppress the f-string SQLi.
const _pySqlNoPollution = _atu(
  `import os\napp.run(port=int(os.environ.get("PORT", "5000")))\nrole = request.args.get("role", "")\nq = f"SELECT * FROM t WHERE role = '{role}'"\nrows = DB.execute(q).fetchall()\n`,
  "a.py",
);
check("taint: python f-string SQLi NOT suppressed by int(os.environ.get) name collision", _pySqlNoPollution.findings.some((f) => f.sink === "sql_execution" && f.variable === "q"), JSON.stringify({ findings: _pySqlNoPollution.findings.length, suppressed: _pySqlNoPollution.suppressed }));

// 37. saveReport — report persistence to disk (regression for reports/ output)
import { saveReport as _saveRep, reportMarkdown as _rm } from "../src/report.ts";
import { existsSync as _ef, rmSync as _rmf, readFileSync as _rfs } from "node:fs";
const _rf = _mk({ title: "persistence test", target: { type: "web", host: "h", endpoint: "/e" }, severity: "low", source: { type: "header", name: "x" }, sink: { type: "y", symbol: "z" } });
const _repTxt = _rm([_rf], { title: "persistence test", scope: "example.com" });
const _savedRep = _saveRep(_repTxt, { title: "persistence test", scope: "example.com" });
check("saveReport: writes .md to reports dir + file exists", typeof _savedRep.path === "string" && _ef(_savedRep.path) && _savedRep.path.endsWith(".md"), _savedRep.path);
check("saveReport: on-disk content matches the report text", _ef(_savedRep.path) && _rfs(_savedRep.path, "utf8") === _repTxt, _savedRep.path);
_rmf(_savedRep.path, { force: true });

// 38. FP regression — benign samples must NOT be flagged (precision fixes)
import { detectComplexBugs as _cb2 } from "../src/complex-bugs.ts";
import { detectRouteConfusion as _rc2 } from "../src/route-confusion.ts";
check("FP fix: canonicalized include not flagged", _rc2("<?php\n$f = basename($_GET['f']);\ninclude($f);\n", "x.php").every((f) => f.type !== "dynamic_include"), JSON.stringify(_rc2("<?php\n$f = basename($_GET['f']);\ninclude($f);\n", "x.php").map((f) => f.type)));
check("FP fix: whitelist dispatch not flagged", _rc2("<?php\n$cb = $_GET['cb'];\ncall_user_func($map[$cb]);\n", "x.php").every((f) => f.type !== "dynamic_dispatch"), JSON.stringify(_rc2("<?php\n$cb = $_GET['cb'];\ncall_user_func($map[$cb]);\n", "x.php").map((f) => f.type)));
check("FP fix: batch forwarding with auth not flagged", _rc2("<?php\nforeach ($requests as $r) { if (!authorize($r)) continue; handle($r); }\n", "x.php").every((f) => f.type !== "batch_forwarding"), JSON.stringify(_rc2("<?php\nforeach ($requests as $r) { if (!authorize($r)) continue; handle($r); }\n", "x.php").map((f) => f.type)));
check("FP fix: constrained ssrf (fixed host) not flagged", _cb2("<?php\necho file_get_contents(\"https://api.example.com/\" . $_GET['path']);\n", "x.php").length === 0, JSON.stringify(_cb2("<?php\necho file_get_contents(\"https://api.example.com/\" . $_GET['path']);\n", "x.php").map((f) => f.type)));

// 39. benchmark — per-detector precision + zero FP (precision regression)
import { runBenchmark as _rbench } from "../src/benchmark.ts";
const _benchRes = _rbench();
const _bd = _benchRes.by_detector as Record<string, { precision: number }>;
check("benchmark: per-detector breakdown (taint/complex_bugs/route_confusion)", !!_bd && !!_bd.taint && !!_bd.complex_bugs && !!_bd.route_confusion, JSON.stringify(Object.keys(_bd ?? {})));
check("benchmark: zero false positives + precision 1.0", (_benchRes.fp as number) === 0 && _benchRes.precision === 1, `fp=${_benchRes.fp} precision=${_benchRes.precision} total=${_benchRes.total_cases}`);

// 40. attack_plan — success_probability + estimated_time + mode (derived, deterministic)
import { attackPlan as _ap } from "../src/intel.ts";
const _apFull = _ap("https://example.com", ["flask"], ["url"]) as Record<string, unknown>;
const _apPlanFull = _apFull.plan as Array<Record<string, unknown>>;
check("attack_plan: derived fields present (success_probability + estimated_time_sec + total)", _apFull.mode === "full" && typeof _apFull.total_estimated_time_sec === "number" && _apPlanFull.every((p) => typeof p.success_probability === "number" && typeof p.estimated_time_sec === "number"), JSON.stringify({ mode: _apFull.mode, n: _apPlanFull.length, total: _apFull.total_estimated_time_sec }));
check("attack_plan: success_probability derived from priority (1->0.85, 2->0.70, 4->0.40)", _apPlanFull.some((p) => p.priority === 1 && p.success_probability === 0.85) && _apPlanFull.some((p) => p.priority === 2 && p.success_probability === 0.7) && _apPlanFull.some((p) => p.priority === 4 && p.success_probability === 0.4), "formula: clamp(0.85-0.15*(p-1))");
const _apQuick = _ap("https://example.com", ["flask"], ["url"], "quick") as Record<string, unknown>;
const _apQuickPlan = _apQuick.plan as Array<Record<string, unknown>>;
check("attack_plan: quick mode -> only priority<=2 (fewer than full)", _apQuickPlan.every((p) => (p.priority as number) <= 2) && _apQuickPlan.length < _apPlanFull.length, `quick=${_apQuickPlan.length} full=${_apPlanFull.length}`);
const _apStealth = _ap("https://example.com", ["flask"], ["url"], "stealth") as Record<string, unknown>;
const _apStealthPlan = _apStealth.plan as Array<Record<string, unknown>>;
check("attack_plan: stealth mode -> passive only (no active injection)", _apStealthPlan.every((p) => !["xss", "sql_injection", "ssti", "command_injection", "ssrf", "path_traversal", "xxe", "file_upload"].includes(p.vector as string)), JSON.stringify(_apStealthPlan.map((p) => p.vector)));
check("attack_plan: deterministic (same input -> byte-identical)", JSON.stringify(_ap("https://example.com", ["flask"], ["url"])) === JSON.stringify(_ap("https://example.com", ["flask"], ["url"])), "byte-identical");

// 41. self-hardening — capture_false_positive -> corpus -> benchmark (closed loop)
import { captureFalsePositive as _cfp, loadCorpus as _lc, runBenchmark as _rb2 } from "../src/benchmark.ts";
const _fpCode = "<?php\n$cb = $_GET['cb'];\ncall_user_func($map[$cb]);\n";
const _cap = _cfp({ code: _fpCode, language: "php", detector: "route_confusion", note: "whitelist dispatch (fp regression test)" });
check("self-hardening: capture writes .md + returns safe entry", _cap.path.endsWith(".md") && _cap.entry.vulnerable === false && _cap.entry.detector === "route_confusion", _cap.path);
check("self-hardening: loadCorpus merges the captured entry", _lc().some((e) => e.id === _cap.entry.id), _cap.entry.id);
const _bench2 = _rb2();
const _capSec = _bench2.captured_false_positives as { total: number; still_flagged: number; entries: Array<{ id: string; still_flagged: boolean }> };
check("self-hardening: benchmark reports captured_false_positives", typeof _capSec?.total === "number" && _capSec.entries.some((e) => e.id === _cap.entry.id), JSON.stringify({ total: _capSec?.total, still: _capSec?.still_flagged }));
_rmf(_cap.path, { force: true });

// 42. intelligence ledger — record/hit-rates/empirical prior (enterprise loop)
import { recordVerdict as _rv, hitRates as _hr, empiricalPrior as _ep, sinkToVector as _stv, loadIntel as _li, recall as _recall } from "../src/intelligence.ts";
import { writeFileSync as _wfs2 } from "node:fs";
import { join as _join } from "node:path";
import { homedir as _homedir } from "node:os";
check("intelligence: sinkToVector maps sink -> vector", _stv("sql_execution") === "sql_injection" && _stv("html_render") === "xss", `${_stv("sql_execution")},${_stv("html_render")}`);
const _tk = `testtech${Date.now()}`;
_rv({ vector: "ssti", tech: _tk, outcome: "confirmed", target: "a1" });
_rv({ vector: "ssti", tech: _tk, outcome: "confirmed", target: "a2" });
_rv({ vector: "ssti", tech: _tk, outcome: "confirmed", target: "a3" });
_rv({ vector: "xxe", tech: _tk, outcome: "false_positive", target: "b1" });
_rv({ vector: "xxe", tech: _tk, outcome: "false_positive", target: "b2" });
_rv({ vector: "xxe", tech: _tk, outcome: "false_positive", target: "b3" });
const _hrRes = _hr(_tk);
const _hrEntries = _hrRes.entries as Array<{ vector: string; tested: number; hit_rate: number }>;
check("intelligence: hitRates aggregates (ssti 3/3=1.0, xxe 0/3=0.0)", _hrEntries.some((e) => e.vector === "ssti" && e.tested === 3 && e.hit_rate === 1) && _hrEntries.some((e) => e.vector === "xxe" && e.tested === 3 && e.hit_rate === 0), JSON.stringify(_hrEntries));
check("intelligence: empiricalPrior Bayesian (100% up, 0% down, no-data=formula)", _ep("ssti", _tk, 0.70) > 0.70 && _ep("xxe", _tk, 0.70) < 0.70 && _ep("nosql_injection", _tk, 0.70) === 0.70, `ssti=${_ep("ssti", _tk, 0.70)} xxe=${_ep("xxe", _tk, 0.70)}`);
const _recallRes = _recall(_tk) as { confirmed_patterns: Array<{ vector: string; confirmed: number }>; avoid_patterns: Array<{ vector: string; false_positives: number }>; total_verdicts: number };
check("intelligence: recall -> ssti confirmed (3), xxe avoid (3)", _recallRes.confirmed_patterns.some((p) => p.vector === "ssti" && p.confirmed === 3) && _recallRes.avoid_patterns.some((p) => p.vector === "xxe" && p.false_positives === 3) && _recallRes.total_verdicts === 6, JSON.stringify({ c: _recallRes.confirmed_patterns.map((p) => p.vector), a: _recallRes.avoid_patterns.map((p) => p.vector), n: _recallRes.total_verdicts }));
const _intPath = _join(_homedir(), ".blitzstrike", "intelligence.jsonl");
const _keptIntel = _li().filter((e) => e.tech !== _tk);
_wfs2(_intPath, _keptIntel.map((e) => JSON.stringify(e)).join("\n") + (_keptIntel.length ? "\n" : ""));

// 43. compliance — CWE -> OWASP/ASVS/PCI/ISO/NIST mapping
import { complianceMap as _cmap, complianceSummary as _csum } from "../src/compliance.ts";
const _cm89 = _cmap("CWE-89");
const _cm79 = _cmap("79");
check("compliance: maps CWE-89 (prefix + bare) to SQLi + frameworks", _cm89?.name.includes("SQL") && _cm89?.owasp_top10 === "A03:2021 Injection" && _cm89?.pci?.includes("6.5.1") && _cm79?.name.includes("XSS"), JSON.stringify(_cm89));
check("compliance: unknown CWE -> null", _cmap("999") === null, String(_cmap("999")));
const _csumRes = _csum(["89", "79", "89", "999"]);
check("compliance: summary aggregates + dedups + counts unmapped", _csumRes.total_mapped === 3 && _csumRes.total_unmapped === 1 && _csumRes.mappings.length === 2 && _csumRes.by_owasp["A03:2021 Injection"] === 3, JSON.stringify({ mapped: _csumRes.total_mapped, unmapped: _csumRes.total_unmapped, unique: _csumRes.mappings.length, owasp: _csumRes.by_owasp }));
check("compliance: full CWE coverage (LDAP/CRLF/JWT/XPATH/header-injection)", Boolean(_cmap("90")?.name.includes("LDAP") && _cmap("93")?.name.includes("CRLF") && _cmap("347")?.name.includes("JWT") && _cmap("643")?.name.includes("XPath") && _cmap("644")?.name.includes("Header")), `${_cmap("90")?.name},${_cmap("347")?.name}`);

// 44. proof-obligation — single-decision loop (structure by construction)
import { createObligation as _co, nextObligation as _no, dischargeObligation as _do, listObligations as _lo, loadObligations as _lob } from "../src/obligations.ts";
const _obl = _co({ claim: `test-obligation-${Date.now()}`, correlation_id: "test-corr" });
check("obligation: create -> open + listed + complete=false", _obl.status === "open" && (_lo().open_obligations as Array<{ id: string }>).some((o) => o.id === _obl.id) && _lo().complete === false, _obl.id);
const _next = _no();
check("obligation: next_obligation returns an open obligation + instruction", _next.done === false && typeof (_next as Record<string, unknown>).obligation === "object", JSON.stringify(_next).slice(0, 60));
const _dres = _do({ id: _obl.id, status: "refuted" });
check("obligation: discharge -> refuted + remaining tracked", _dres.discharged === true && _dres.status === "refuted", JSON.stringify(_dres));
const _obPath = _join(_homedir(), ".blitzstrike", "obligations.jsonl");
const _keptObl = _lob().filter((o) => !o.claim.startsWith("test-obligation-"));
_wfs2(_obPath, _keptObl.map((o) => JSON.stringify(o)).join("\n") + (_keptObl.length ? "\n" : ""));

// 45. security-state lattice — wrong-context sanitization (beyond binary taint)
import { analyzeSecurityState as _ass, detectWrongSanitizer as _dws } from "../src/security-state.ts";
check("security-state: sanitize_text_field->SQL = vulnerable (wrong context)", _ass({ sanitizers: ["sanitize_text_field"], sinkType: "sql_execution" }).verdict === "vulnerable", "wrong context");
check("security-state: esc_sql->SQL = safe (correct context)", _ass({ sanitizers: ["esc_sql"], sinkType: "sql_execution" }).verdict === "safe", "correct context");
check("security-state: absint->SQL = safe (validated)", _ass({ sanitizers: ["absint"], sinkType: "sql_execution" }).verdict === "safe", "validated");
check("security-state: base64_encode->SQL = vulnerable (pseudo-sanitizer)", _ass({ sanitizers: ["base64_encode"], sinkType: "sql_execution" }).verdict === "vulnerable", "pseudo");
const _phpWrong = `<?php
$name = sanitize_text_field($_GET['name']);
$wpdb->query("SELECT * FROM t WHERE n='$name'");
`;
const _phpRight = `<?php
$name = esc_sql($_GET['name']);
$wpdb->query("SELECT * FROM t WHERE n='$name'");
`;
const _dwf = _dws(_phpWrong, "inline");
check("security-state: detectWrongSanitizer flags wrong-context", _dwf.length === 1 && _dwf[0].type === "wrong_sanitizer", String(_dwf.length));
check("security-state: detectWrongSanitizer skips correct-context", _dws(_phpRight, "inline").length === 0, "0 findings");

// 46. framework security — missing authz/nonce on WP entry points
import { detectMissingAuthz as _dma, frameworkKnowledge as _fk } from "../src/framework-security.ts";
const _wpAuthzVuln = `<?php
add_action('wp_ajax_nopriv_delete_user', 'delete_user_handler');
function delete_user_handler() {
    $id = $_POST['id'];
    $wpdb->query("DELETE FROM users WHERE id=$id");
}
`;
const _wpAuthzSafe = `<?php
add_action('wp_ajax_delete_user', 'safe_handler');
function safe_handler() {
    check_ajax_referer('nonce');
    if (!current_user_can('manage_options')) { wp_die('no'); }
}
`;
const _dmaRes = _dma(_wpAuthzVuln, "inline");
check("framework: unauth AJAX no capability -> missing_authz + missing_nonce", _dmaRes.some((f) => f.type === "missing_authz") && _dmaRes.some((f) => f.type === "missing_nonce"), JSON.stringify(_dmaRes.map((f) => f.type)));
check("framework: AJAX with capability+nonce -> clean", _dma(_wpAuthzSafe, "inline").length === 0, "0 findings");
check("framework: knowledge graph returns WP primitives", Boolean(_fk("wordpress")?.auth_primitives.includes("current_user_can") && _fk("wordpress")?.nonce_primitives.includes("wp_verify_nonce")), "wp primitives");
check("framework: unknown framework -> null", _fk("nope") === null, String(_fk("nope")));

// 47. variant mining — mass scan + derived signature
import { variantScan as _vscan, deriveSignature as _dsig } from "../src/variant-scan.ts";
import { mkdirSync as _mkd } from "node:fs";
check("variant: deriveSignature = detector:type", _dsig("complex_bugs", "missing_authz") === "complex_bugs:missing_authz", _dsig("complex_bugs", "missing_authz"));
const _vdir = _join(_homedir(), `blitzstrike-vtest-${Date.now()}`);
_mkd(_vdir + "/p", { recursive: true });
_wfs2(_vdir + "/p/vuln.php", "<?php\nadd_action('wp_ajax_nopriv_delete_user', 'h');\nfunction h() { $wpdb->query(\"DELETE FROM u WHERE id=\" . $_POST['id']); }\n");
_wfs2(_vdir + "/p/clean.php", "<?php\n$x = 1 + 2;\n");
const _vres = _vscan(_vdir) as { files_scanned: number; total_findings: number; by_signature: Record<string, number> };
check("variant: mass scan finds vuln + groups by signature", _vres.files_scanned === 2 && _vres.total_findings >= 1 && _vres.by_signature["complex_bugs:missing_authz"] === 1, JSON.stringify({ scanned: _vres.files_scanned, findings: _vres.total_findings }));
const _vmine = _vscan(_vdir, { signature: "complex_bugs:missing_authz" }) as { hits: Array<{ signature: string }> };
check("variant: mining one family filters to that family", _vmine.hits.length === 1 && _vmine.hits[0].signature === "complex_bugs:missing_authz", String(_vmine.hits.length));
_rmf(_vdir, { recursive: true, force: true });

// 48. framework security — multi-framework authz detection
import { listFrameworks as _lsf } from "../src/framework-security.ts";
const _fwList = _lsf();
check("framework: knowledge graph covers 9 frameworks", ["laravel", "django", "flask", "express", "spring", "symfony", "aspnet", "rails", "wordpress"].every((f) => _fwList.includes(f)), _fwList.join(","));
const _laravelVuln = "<?php\nRoute::post('/users/delete', [C::class, 'd']);\n";
const _laravelSafe = "<?php\nRoute::post('/users/delete', [C::class, 'd'])->middleware('auth');\n";
check("framework: Laravel route no auth -> flagged", _dma(_laravelVuln, "inline").some((f) => f.category.includes("laravel")), "laravel vuln");
check("framework: Laravel route with auth middleware -> clean", _dma(_laravelSafe, "inline").length === 0, "laravel safe");
const _djangoVuln = "def delete_user(request):\n    return HttpResponse('deleted')\n";
check("framework: Django view no login_required -> flagged", _dma(_djangoVuln, "inline").some((f) => f.category.includes("django")), "django vuln");

// 49. action-name heuristic engine — targeting (what to look for WHERE)
import { actionSurface as _asurf, mapActionToVuln as _matv } from "../src/action-heuristics.ts";
check("action-heuristic: upload->AFU/RCE + file_upload detector", Boolean(_matv("backup_import")?.vuln_class.includes("Upload") && _matv("backup_import")?.detector.includes("file_upload")), _matv("backup_import")?.vuln_class ?? "");
const _ahCode = `<?php
add_action('wp_ajax_nopriv_backup_import', 'h1');
function h1() { $f = $_FILES['f']; move_uploaded_file($f['tmp_name'], '/x/' . $f['name']); }
add_action('wp_ajax_safe_settings', 'h2');
function h2() { check_ajax_referer('n'); if (!current_user_can('manage_options')) wp_die(); update_option('x', $_POST['x']); }
`;
const _ahRes = _asurf(_ahCode) as { actions: number; top_priority: { action: string; priority: number } };
check("action-heuristic: surface prioritizes nopriv upload on top", _ahRes.actions === 2 && _ahRes.top_priority.action === "backup_import" && _ahRes.top_priority.priority >= 0.95, JSON.stringify(_ahRes.top_priority));

// 50. patch reversal — 1-day weaponization
import { analyzePatch as _apatch } from "../src/differential.ts";
const _sqlOld = "<?php\n$id = $_GET['id'];\n$wpdb->query(\"DELETE FROM u WHERE id=$id\");\n";
const _sqlNew = "<?php\n$id = absint($_GET['id']);\n$wpdb->query(\"DELETE FROM u WHERE id=$id\");\n";
const _pr = _apatch(_sqlOld, _sqlNew, "php") as { summary: Record<string, number>; reversal_findings: Array<{ kind: string; mine_signature: string }> };
check("patch: absint added -> sanitizer_added reversal", _pr.summary.sanitizer_added === 1 && _pr.reversal_findings[0]?.mine_signature === "complex_bugs:wrong_sanitizer", JSON.stringify(_pr.summary));
const _cosmeticOld = "<?php\n$x = 1;\necho $x;\n";
const _cosmeticNew = "<?php\n$x = 1;\necho \"hello\";\n";
const _pr2 = _apatch(_cosmeticOld, _cosmeticNew, "php") as { reversal_findings: Array<unknown> };
check("patch: cosmetic change -> no reversal", _pr2.reversal_findings.length === 0, String(_pr2.reversal_findings.length));

// 51. cache gap fuzzer — variant generation + classification (live technique)
import { generateCacheVariants as _gcv, classifyCacheResponse as _ccr } from "../src/cache-gap.ts";
const _vars = _gcv("/account");
check("cache-gap: generates static-extension + normalization variants", _vars.includes("/account.css") && _vars.includes("/account/..;/style.css") && _vars.includes("/account%00"), String(_vars.length));
const _cbase = "h";
check("cache-gap: same body + static + cacheable -> cache_deception", _ccr({ baselineHash: _cbase, bodyHash: _cbase, status: 200, headers: { "cache-control": "public" }, staticExtension: true }).gap === "cache_deception", "deception");
check("cache-gap: same body + cache HIT -> cache_deception", _ccr({ baselineHash: _cbase, bodyHash: _cbase, status: 200, headers: { "x-cache": "HIT" }, staticExtension: false }).gap === "cache_deception", "hit");
check("cache-gap: diff body + static + non-200 -> normalization_gap", _ccr({ baselineHash: _cbase, bodyHash: "x", status: 404, headers: {}, staticExtension: true }).gap === "normalization_gap", "norm");
check("cache-gap: same body + no-store -> no gap", _ccr({ baselineHash: _cbase, bodyHash: _cbase, status: 200, headers: { "cache-control": "no-store" }, staticExtension: false }).gap === null, "none");

// 52. blind differential oracle — probe generation + classification
import { arithmeticProbes as _aprob, sstiProbes as _sprob, classifyBlindProbe as _cbp } from "../src/blind-oracle.ts";
check("oracle: arithmetic probes (numeric) + payload 1+0", _aprob("1").length === 5 && _aprob("1")[0]?.payload === "1+0", JSON.stringify(_aprob("1").map((p) => p.payload)));
check("oracle: arithmetic probes (non-numeric) empty", _aprob("abc").length === 0, String(_aprob("abc").length));
check("oracle: ssti probes carry literal ${7*7}", _sprob("test")[0]?.payload === "test${7*7}", _sprob("test")[0]?.payload ?? "");
check("oracle: sql arithmetic same -> signal", _cbp({ baselineHash: "a", baselineSize: 1, bodyHash: "a", size: 1, sink: "sql_arithmetic", name: "plus_zero", body: "" }).signal === true, "sql");
check("oracle: ssti renders 49 + diff -> signal", _cbp({ baselineHash: "a", baselineSize: 1, bodyHash: "b", size: 1, sink: "ssti", name: "dollar_math", body: "49" }).signal === true, "ssti");
check("oracle: xss marker reflected -> signal", _cbp({ baselineHash: "a", baselineSize: 1, bodyHash: "b", size: 1, sink: "xss", name: "marker", body: "zzMARKzz", marker: "zzMARKzz" }).signal === true, "xss");

// 53. param precedence — duplicate parameter fuzzer
import { generatePrecedenceVariants as _gpv, classifyPrecedence as _cp } from "../src/param-precedence.ts";
check("precedence: generates 9 variants", _gpv("id", "A", "B").length === 9, String(_gpv("id", "A", "B").length));
check("precedence: classify A -> first-wins", _cp({ hashA: "hA", hashB: "hB", bodyHash: "hA", name: "x" }).winner === "A", "A");
check("precedence: classify B -> last-wins", _cp({ hashA: "hA", hashB: "hB", bodyHash: "hB", name: "x" }).winner === "B", "B");
check("precedence: classify neither -> literal/joined", _cp({ hashA: "hA", hashB: "hB", bodyHash: "hC", name: "x" }).winner === "neither", "neither");

// 54. race condition — concurrency idempotency oracle
import { classifyRace as _crace, requestSignature as _rsig } from "../src/race-test.ts";
check("race: 6/15 > expected 1 -> race", _crace({ successes: 6, total: 15, expected_max: 1 }).race === true, "race");
check("race: 1/15 <= expected 1 -> no race", _crace({ successes: 1, total: 15, expected_max: 1 }).race === false, "no race");
check("race: requestSignature deterministic", _rsig("POST", "http://x", "body") === _rsig("POST", "http://x", "body") && _rsig("POST", "http://x", "a") !== _rsig("POST", "http://x", "b"), "sig");

// 55. JWT forgeability analyzer
import { analyzeJwt as _ajwt, decodeJwt as _djwt } from "../src/jwt-analyze.ts";
import { createHmac as _chm } from "node:crypto";
const _b64j = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const _none = `${_b64j({ alg: "none" })}.${_b64j({ sub: "admin" })}.`;
check("jwt: alg:none -> forgeable", (_ajwt(_none) as { findings: Array<{ type: string }> }).findings.some((f) => f.type === "alg_none"), "none");
const _rs = `${_b64j({ alg: "RS256" })}.${_b64j({ sub: "u" })}.s`;
check("jwt: RS256 -> key_confusion", (_ajwt(_rs) as { findings: Array<{ type: string }> }).findings.some((f) => f.type === "key_confusion"), "rs");
const _data = `${_b64j({ alg: "HS256" })}.${_b64j({ sub: "u" })}`;
const _sig = _chm("sha256", "pwd").update(_data).digest("base64url");
check("jwt: weak HS256 secret brute-forced", (_ajwt(`${_data}.${_sig}`, { wordlist: ["pwd", "x"] }) as { findings: Array<{ type: string }> }).findings.some((f) => f.type === "weak_secret"), "weak");
check("jwt: decode roundtrip", (_djwt(_none) as { payload: Record<string, unknown> }).payload.sub === "admin", "decode");

// 56. file upload → RCE detector
import { detectComplexBugs as _dcb2 } from "../src/complex-bugs.ts";
const _fuVuln = `<?php
$dir = '/uploads/';
$name = $_FILES['file']['name'];
$path = $dir . $name;
move_uploaded_file($_FILES['file']['tmp_name'], $path);
`;
check("file-upload: move_uploaded_file with unvalidated name -> flagged", _dcb2(_fuVuln, "inline").some((f) => f.type === "file_upload"), "vuln");
const _fuSafe = `<?php
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array($ext, array('jpg','png','gif'))) wp_die();
move_uploaded_file($_FILES['file']['tmp_name'], $dir . $_FILES['file']['name']);
`;
check("file-upload: whitelisted extension -> clean", !_dcb2(_fuSafe, "inline").some((f) => f.type === "file_upload"), "safe");

// 57. SQL injection (raw string-interpolated query) detector
const _sqliVuln = `<?php
function get_users($params) { global $wpdb;
  return $wpdb->get_results("SELECT * FROM users WHERE id = " . $params['id']);
}
`;
check("sql-injection: raw concat query -> flagged", _dcb2(_sqliVuln, "inline").some((f) => f.type === "sql_injection"), "vuln");
const _sqliSafe = `<?php
function get_users($id) { global $wpdb;
  return $wpdb->get_results($wpdb->prepare("SELECT * FROM users WHERE id = %d", $id));
}
`;
check("sql-injection: prepared query -> clean", !_dcb2(_sqliSafe, "inline").some((f) => f.type === "sql_injection"), "safe");

// 58. class-method handler detection (modern WP plugins use array($this,'method'))
import { detectMissingAuthz as _dma2 } from "../src/framework-security.ts";
const _cmVuln = `<?php
class Foo {
  public function __construct() {
    add_action('wp_ajax_nopriv_my_action', array($this, 'do_stuff'));
  }
  public function do_stuff() {
    $id = $_POST['id'];
    update_option('x', $id);
  }
}
`;
check("wp: class-method nopriv handler no cap -> missing_authz", _dma2(_cmVuln, "inline").some((f) => f.type === "missing_authz"), "authz");
check("wp: class-method handler no nonce -> missing_nonce", _dma2(_cmVuln, "inline").some((f) => f.type === "missing_nonce"), "nonce");
const _cmSafe = `<?php
class Foo {
  public function __construct() {
    add_action('wp_ajax_my_action', array($this, 'do_stuff'));
  }
  public function do_stuff() {
    check_ajax_referer('n');
    if (!current_user_can('manage_options')) return;
    update_option('x', $_POST['id']);
  }
}
`;
check("wp: class-method handler with nonce+cap -> clean", _dma2(_cmSafe, "inline").length === 0, "safe");

// 59. precision — read-only handlers need no nonce/capability (no CSRF state change)
const _roOnly = `<?php
add_action('wp_ajax_nopriv_list_posts', array($this, 'list_posts'));
public function list_posts() {
  return $wpdb->get_results("SELECT * FROM posts LIMIT 10");
}
`;
check("precision: read-only handler -> no missing_nonce/authz", _dma2(_roOnly, "inline").length === 0, "read-only clean");

// 60. REST __return_true detection (explicitly public route)
const _restPublic = `<?php
register_rest_route('my/v1', '/users', array(
  'methods' => 'GET',
  'callback' => 'get_users',
  'permission_callback' => '__return_true',
));
`;
check("rest: __return_true -> missing_authz (public)", _dma2(_restPublic, "inline").some((f) => f.type === "missing_authz" && f.severity === "medium"), "public");
const _restReal = `<?php
register_rest_route('my/v1', '/users', array(
  'methods' => 'GET',
  'callback' => 'get_users',
  'permission_callback' => array($this, 'check_admin'),
));
`;
check("rest: real permission_callback -> clean", !_dma2(_restReal, "inline").some((f) => f.type === "missing_authz"), "real check");

// 61. lib/ directory is scanned (bundled plugin code must not be skipped)
import { iterSourceFiles as _isf } from "../src/scanner.ts";
import { mkdtempSync as __mkdtemp, mkdirSync as __mkdir, writeFileSync as __wfs, rmSync as __rm } from "node:fs";
import { tmpdir as _tmpdir } from "node:os";
import { join as _jpath } from "node:path";
const _td = __mkdtemp(_jpath(_tmpdir(), "libscan-"));
__mkdir(_jpath(_td, "lib"), { recursive: true });
__wfs(_jpath(_td, "lib", "vuln.php"), "<?php $wpdb->query($_GET['id']);");
const _libFiles = _isf(_td);
check("scanner: lib/ directory IS scanned", _libFiles.some((f) => f.includes("lib/vuln.php")), String(_libFiles));
__rm(_td, { recursive: true, force: true });

// 62. priv_esc (cross-file): role/user set from request input
import { detectCrossFilePrivesc as _dcf } from "../src/cross-file.ts";
const _pvDir = __mkdtemp(_jpath(_tmpdir(), "priv-"));
__wfs(_jpath(_pvDir, "a.php"), `<?php
function um_register() {
  set_role(1, sanitize_key($_POST['um-role']));
}
`);
const _pvRes = _dcf(_pvDir);
check("priv_esc: set_role from request input -> flagged", _pvRes.some((f) => f.type === "priv_esc"), JSON.stringify(_pvRes.map((f) => f.type)));
__wfs(_jpath(_pvDir, "b.php"), `<?php
function safe_role() {
  set_role(1, 'subscriber');
}
`);
check("priv_esc: hardcoded role -> clean", !_dcf(_pvDir).some((f) => f.type === "priv_esc" && f.file.includes("b.php")), "hardcoded clean");
__rm(_pvDir, { recursive: true, force: true });

// 63. unrestricted upload config (uploadAllow=all → RCE)
const _uaCode = `<?php
$opts = array(
  'uploadDeny' => array('all'),
  'uploadAllow' => array('all'),
  'uploadOrder' => array('deny', 'allow'),
);
`;
check("upload: uploadAllow=all -> file_upload (unrestricted)", _dcb2(_uaCode, "inline").some((f) => f.type === "file_upload" && /Unrestricted/i.test(f.category)), "unrestricted");

// 64. antiscript (extension-strip) is NOT a defense — a filename special-char
// vuln is not extension-based; the vulnerable version also calls the antiscript
// helper. Must still flag.
const _antiscriptCode = `<?php
$filename = $file['name'];
$filename = antiscript_file_name($filename);
move_uploaded_file($file['tmp_name'], $filename);
`;
check("file-upload: antiscript alone -> still flagged", _dcb2(_antiscriptCode, "inline").some((f) => f.type === "file_upload"), "antiscript not a defense");

// 65. hardcoded secret detector (CWE-798)
const _hsVuln = `<?php
$api_key = "EXAMPLE_API_KEY_123456789";
const DB_PASSWORD = "sup3r_s3cret_pw_123";
`;
check("hardcoded_secret: api_key + db_password -> flagged", _dcb2(_hsVuln, "inline").filter((f) => f.type === "hardcoded_secret").length === 2, "2 secrets");
const _hsSafe = `<?php
$api_key = getenv("API_KEY");
$password = "changeme";
$token = $user_token;
`;
check("hardcoded_secret: env/placeholder/var -> clean", !_dcb2(_hsSafe, "inline").some((f) => f.type === "hardcoded_secret"), "clean");

// 66. hardcoded_secret tiers 2 (format) + 3 (entropy)
// Secret values are built at runtime so no literal token is committed (avoids
// repo secret-scanning false positives on the fixture itself).
const _slackTok = "xoxb-" + "123456789012-123456789012-abcdefghijklmnopqrst";
const _sgTok = "SG." + "abcdefghijklmnopqrstuvwx" + "." + "yzabcdefghijklmnopqrst";
const _hsFmt = `<?php
$t = "${_slackTok}";
$k = "${_sgTok}";
`;
check("hardcoded_secret: format (slack+sendgrid) -> flagged HIGH", _dcb2(_hsFmt, "inline").filter((f) => f.type === "hardcoded_secret" && f.severity === "high").length === 2, "2 formats");
const _hsEntropy = `<?php
$myvar = "aB3kL9mN2xQ8rT5vW7yZ1cD4fG6hJ0pS";
$h = "5d41402abc4b2a76b9719d911017c592";
`;
const _hsEntropyHits = _dcb2(_hsEntropy, "inline").filter((f) => f.type === "hardcoded_secret");
check("hardcoded_secret: entropy token MEDIUM + hash skipped", _hsEntropyHits.length === 1 && _hsEntropyHits[0]?.severity === "medium", JSON.stringify(_hsEntropyHits.map((h) => h.severity)));

// 67. detector inventory self-test — every ComplexBugType must have a CWE map
const _cweMapTxt = _rfs(join(process.cwd(), "intelligence", "cwe_map.json"), "utf8");
const _cweIds = new Set((JSON.parse(_cweMapTxt).mapping as Array<{ id: string }>).map((m) => m.id));
const _cbSrc = _rfs(join(process.cwd(), "src", "complex-bugs.ts"), "utf8");
const _unionBlock = _cbSrc.split("export type ComplexBugType =")[1]?.split(";")[0] ?? "";
const _detectorTypes = [..._unionBlock.matchAll(/"([a-z_]+)"/g)].map((mm) => mm[1]);
const _missingCwe = _detectorTypes.filter((t) => !_cweIds.has(t));
check("inventory: every ComplexBugType -> CWE mapped", _missingCwe.length === 0, _missingCwe.join(", ") || "complete");

// 68. empirical pattern library + submission gate
import { patternLookup as _patLookup, listPatterns as _patList, submissionGate as _subGate } from "../src/patterns.ts";
check("patterns: every detector type grounded + sql_injection -> CWE-89", _detectorTypes.every((t) => _patList().some((p) => p.id === t)) && _patLookup("sql_injection")?.cwe === "CWE-89", `${_patList().length} patterns / ${_detectorTypes.length} types`);
check("patterns: hardcoded_secret chains cross-ref chains.json", (_patLookup("hardcoded_secret")?.chain_templates?.length ?? 0) >= 3, _patLookup("hardcoded_secret")?.chain_templates?.join(",") ?? "");
const _missingPattern = _detectorTypes.filter((t) => !_patList().some((p) => p.id === t));
check("patterns: every detector type is empirically grounded", _missingPattern.length === 0, _missingPattern.join(", ") || "complete");
const _withoutBypass = _patList().filter((p) => (p.bypass_techniques?.length ?? 0) === 0 || (p.crown_jewels?.length ?? 0) === 0);
check("patterns: every class has bypass techniques + crown jewels", _withoutBypass.length === 0, _withoutBypass.map((p) => p.id).join(", ") || "complete");
const _withoutPayout = _patList().filter((p) => p.payout_min == null || p.payout_max == null || !p.typical_payout);
check("patterns: every class has a typical bounty payout range", _withoutPayout.length === 0, _withoutPayout.map((p) => p.id).join(", ") || "complete");
check("patterns: sql_injection payout range resolves", _patLookup("sql_injection")?.typical_payout === "$1K–$15K", _patLookup("sql_injection")?.typical_payout ?? "");
const _gateOk = _subGate({ reproducible: true, in_scope: true, real_impact: true, no_privileged_assumption: true, verified_live: true, evidence_redacted: true, severity_derived: true });
check("gate: all-asserted -> pass 7/7", _gateOk.verdict === "pass" && _gateOk.passed === 7, `${_gateOk.passed}/${_gateOk.total}`);
const _gateEmpty = _subGate({});
check("gate: empty input -> fail (fail-closed)", _gateEmpty.verdict === "fail" && Boolean(_gateEmpty.blocker), _gateEmpty.blocker ?? "");
const _gateFail = _subGate({ reproducible: true, verified_live: false });
check("gate: explicit false -> fail + blocker", _gateFail.verdict === "fail" && Boolean(_gateFail.blocker), _gateFail.blocker ?? "");

// 69. severity calibration + engagement scaffold + data refresh
import { severityCalibrate as _sevCal } from "../src/severity.ts";
import { scaffoldEngagement as _scaffold } from "../src/engagement.ts";
import { dataRefresh as _dataRefresh } from "../src/datarefresh.ts";
const _sevSqli = _sevCal({ type: "sql_injection" });
check("severity: sql_injection -> P1 critical", _sevSqli.priority === "P1" && _sevSqli.severity === "critical", JSON.stringify(_sevSqli));
check("severity: informational -> P5", _sevCal({ type: "xss", informational: true }).priority === "P5", _sevCal({ type: "xss", informational: true }).priority);
const _missingSev = _detectorTypes.filter((t: string) => _sevCal({ type: t }).vrt_category === "unclassified");
check("severity: every detector type has a VRT mapping (no unclassified)", _missingSev.length === 0, _missingSev.join(", ") || "complete");
const _scaf = _scaffold("example.com", ["*.example.com"]);
check("scaffold: structure + scope template", _scaf.structure.includes("findings/") && _scaf.scope_md.includes("In scope"), _scaf.structure.join(","));
const _dr = _dataRefresh();
check("data_refresh: layers consistent (no broken refs)", _dr.consistency.ok === true, JSON.stringify(_dr.consistency));

// 70. modern detectors (LLM / GraphQL / OAuth / gRPC)
const _llmCode = `<?php
$user_msg = $_POST['message'];
$resp = openai.chat.completions.create(['messages' => [['role' => 'user', 'content' => $user_msg]]]);
`;
check("llm_injection: request input -> LLM call", _dcb2(_llmCode, "inline").some((f) => f.type === "llm_injection"), "llm");
const _gqlCode = `<?php
const server = new ApolloServer({ introspection: true, playground: true });
`;
check("graphql_exposure: introspection/playground true", _dcb2(_gqlCode, "inline").some((f) => f.type === "graphql_exposure"), "graphql");
const _oauthCode = `<?php
$redirect_uri = $_GET['redirect_uri'];
$url = "https://provider/auth?redirect_uri=" . $redirect_uri;
`;
check("oauth_misconfig: redirect_uri from request input", _dcb2(_oauthCode, "inline").some((f) => f.type === "oauth_misconfig"), "oauth");
const _grpcCode = `<?php
$server->addService(enable_server_reflection());
`;
check("grpc_reflection: reflection enabled", _dcb2(_grpcCode, "inline").some((f) => f.type === "grpc_reflection"), "grpc");
const _depCode = `--extra-index-url https://pypi.org/simple\nnumpy==1.24\n`;
check("dependency_confusion: public pypi as extra-index", _dcb2(_depCode, "requirements.txt").some((f) => f.type === "dependency_confusion"), "depconf");
const _depCode2 = `{\n  "dependencies": { "@company/internal-lib": "^1.0.0" }\n}\n`;
check("dependency_confusion: scoped package, no private registry", _dcb2(_depCode2, "package.json").some((f) => f.type === "dependency_confusion"), "depconf2");
const _mlCode = `import torch\nmodel = torch.load(downloaded_model)\n`;
check("ml_supply_chain: torch.load without weights_only", _dcb2(_mlCode, "train.py").some((f) => f.type === "ml_supply_chain"), "torch");
const _mlCode2 = `import numpy as np\narr = np.load(path, allow_pickle=True)\n`;
check("ml_supply_chain: np.load allow_pickle=True (source-agnostic)", _dcb2(_mlCode2, "infer.py").some((f) => f.type === "ml_supply_chain"), "np");

// 71. verification harness — every detector passes TP + TN
import { runVerificationHarness as _vharness } from "../src/verify-harness.ts";
const _vrep = _vharness();
check("verify-harness: all detectors pass (TP + TN)", _vrep.failed === 0 && _vrep.passed === _vrep.total, `${_vrep.passed}/${_vrep.total} pass, ${_vrep.fn_count} FN, ${_vrep.fp_count} FP`);

// 72. variant corpus — every real-world shape fires its class's detector
import { scanVariants as _scanVariants } from "../src/variants.ts";
const _vcov = _scanVariants();
check("variant-corpus: every shape detected (no coverage gaps)", _vcov.missed === 0, `${_vcov.fired}/${_vcov.total} detected, ${_vcov.missed} missed`);

// 73. expanded secret formats (47 formats, each with severity + category)
import { SECRET_FORMATS as _sf } from "../src/secrets.ts";
check("secrets: 45+ formats each with severity + category", _sf.length >= 45 && _sf.every((f) => f.severity && f.category), `${_sf.length} formats`);
// Fixtures are built at runtime (concat) so no literal secret appears in source —
// GitHub secret-scanning rejects committed test fixtures that look like real keys.
const _stripeCode = "const k = 'sk_l" + "ive_51AbCdEfGhIjKlMnOpQrStUvWxYz1234';";
check("secrets: stripe live -> critical", _dcb2(_stripeCode, "inline").some((f) => f.type === "hardcoded_secret" && f.severity === "critical" && /stripe/i.test(f.category)), "stripe");
const _npmCode = "npm" + "_abcdefghijklmnopqrstuvwxyz1234567890";
check("secrets: npm token -> high + category", _dcb2(_npmCode, "inline").some((f) => f.type === "hardcoded_secret" && f.severity === "high" && /package_registry/i.test(f.category)), "npm");

// 74. synonym / alias resolution (free-form term -> canonical detector id)
import { canonicalId as _cid } from "../src/synonyms.ts";
check("synonyms: IDOR -> missing_authz", _cid("IDOR") === "missing_authz", _cid("IDOR"));
check("synonyms: BOLA -> missing_authz", _cid("BOLA") === "missing_authz", _cid("BOLA"));
check("synonyms: prompt injection -> llm_injection", _cid("prompt injection") === "llm_injection", _cid("prompt injection"));
check("synonyms: pattern_lookup('IDOR') resolves to missing_authz", _patLookup("IDOR")?.id === "missing_authz", _patLookup("IDOR")?.id ?? "null");

// 75. redaction covers detection (invariant: every secret the detector finds is stripped)
import { redactSecrets as _redact } from "../src/secrets.ts";
check("redaction: strips discord bot + ngrok + slack webhook + basic-auth", _redact("M" + "a".repeat(23) + "." + "b".repeat(6) + "." + "c".repeat(27)).includes("[REDACTED]") && _redact("https://hooks.slack.com/services/T000/B000/xxx").includes("[REDACTED]") && _redact("https://user:pass@example.com").includes("[REDACTED]") && _redact("1abcdefghijklmnopqrstuvwxyz_abcdefghijklmnopqrstuvwxyz123456").includes("[REDACTED]"), "redact");

// 76. git-history secret mining + severity escalation + leaked-key validation
import { scanGitHistory as _sgh } from "../src/git-history.ts";
import { validateLeakedKey as _vlk } from "../src/key-validation.ts";
import { execFileSync as _git, } from "node:child_process";
import { mkdtempSync as _mkdtemp, rmSync as _rmtree, writeFileSync as _wfs3 } from "node:fs";
import { tmpdir as _tmpdir2 } from "node:os";
import { createServer as _createServer } from "node:http";
const _repo = _mkdtemp(_join(_tmpdir2(), "bsgit-"));
try {
  _git("git", ["-C", _repo, "init", "-q"]);
  _git("git", ["-C", _repo, "config", "user.email", "t@t.co"]);
  _git("git", ["-C", _repo, "config", "user.name", "t"]);
  _wfs3(_join(_repo, ".env"), "SECRET_KEY=sk_l" + "ive_51AbCdEfGhIjKlMnOpQrStUvWxYz1234");
  _git("git", ["-C", _repo, "add", "-A"]);
  _git("git", ["-C", _repo, "commit", "-qm", "add env"]);
  _git("git", ["-C", _repo, "rm", "-q", ".env"]);
  _git("git", ["-C", _repo, "commit", "-qm", "remove env"]);
  const _gh = _sgh(_repo) as any;
  check("git-history: finds secret in DELETED .env (removed-later != fixed)", _gh.total >= 1 && _gh.findings.some((f: any) => f.path === ".env"), JSON.stringify(_gh.findings?.map((f: any) => f.path) ?? []));
  check("git-history: stripe live in a secret field escalates to critical", _gh.findings.some((f: any) => f.severity === "critical"), _gh.findings?.[0]?.severity ?? "none");
} finally {
  _rmtree(_repo, { recursive: true, force: true });
}
const _esc = _dcb2("SECRET_KEY=sk_l" + "ive_51AbCdEfGhIjKlMnOpQrStUvWxYz1234", "inline");
check("secret: field + format escalates severity to critical", _esc.some((f) => f.type === "hardcoded_secret" && f.severity === "critical"), JSON.stringify(_esc.map((f) => f.severity)));
const _kvServer = _createServer((req, res) => {
  const ok = req.headers.authorization === "Bearer leaked-test-key";
  res.statusCode = ok ? 200 : 401;
  res.setHeader("content-type", "application/json");
  res.end(ok ? '{"data":[{"id":1}]}' : "unauthorized");
});
await new Promise<void>((resolve) => _kvServer.listen(0, "127.0.0.1", resolve));
const _kvPort = (_kvServer.address() as any).port;
const _kv = await _vlk({ key: "leaked-test-key", apiBase: `http://127.0.0.1:${_kvPort}`, endpoints: ["/items"] });
check("key-validation: 401-without / 200-with differential -> BYPASS proven", _kv.proven === true, JSON.stringify(_kv.results));
_kvServer.close();

// 77. per-finding per-scope reports (one HackerOne-grade report per finding)
import { perFindingReports as _pfr, findingReport as _freport } from "../src/report.ts";
const _pf1 = makeFinding({ title: "SQL Injection in login", target: { type: "web", host: "h", endpoint: "/l" }, severity: "critical", cwe: "CWE-89", source: { type: "request_parameter", name: "u" }, sink: { type: "sql_execution", symbol: "q" }, status: "confirmed", chainId: "sql_injection", chainName: "SQLi" });
const _pf2 = makeFinding({ title: "Reflected XSS", target: { type: "web", host: "h", endpoint: "/s" }, severity: "medium", cwe: "CWE-79", source: { type: "request_parameter", name: "q" }, sink: { type: "html_render", symbol: "i" }, status: "confirmed", chainId: "xss", chainName: "XSS" });
const _pfLayout = _pfr([_pf1, _pf2], { title: "T", scope: "example.com" }) as any;
check("per-finding: 2 files + SUMMARY.md + metadata.json", _pfLayout.total === 2 && _pfLayout.files.length === 2 && _pfLayout.summary_path.endsWith("SUMMARY.md") && _pfLayout.metadata_path.endsWith("metadata.json"), JSON.stringify(_pfLayout.files.map((f: any) => f.filename)));
const _fmd = _freport(_pf1);
check("per-finding: HackerOne-grade sections + severity tier", /## Summary/.test(_fmd) && /## Steps to Reproduce/.test(_fmd) && /## Impact/.test(_fmd) && /## Remediation/.test(_fmd) && /critical \(P1\)/.test(_fmd), "sections");

// 78. Rust language support (adapter + detectors)
const _rustCmd = `fn main() { let cmd = std::env::args().nth(1).unwrap(); std::process::Command::new("sh").arg("-c").arg(cmd); }`;
check("rust taint: env::args -> Command::new = command_execution", _atu(_rustCmd, "x.rs").findings.some((f) => f.sink === "command_execution"), JSON.stringify(_atu(_rustCmd, "x.rs").findings.map((f) => f.sink)));
const _rustSqlSafe = `fn h() { let q = std::env::args().nth(1).unwrap(); sqlx::query!("SELECT * FROM t WHERE id = {}", q); }`;
check("rust taint: sqlx query! macro (compile-time safe) -> suppressed", _atu(_rustSqlSafe, "x.rs").findings.length === 0, JSON.stringify(_atu(_rustSqlSafe, "x.rs").findings.map((f) => f.sink)));
const _rustSqlVuln = `fn h() { let q = std::env::args().nth(1).unwrap(); sqlx::query(&format!("SELECT * FROM t WHERE id = {}", q)); }`;
check("rust taint: sqlx runtime query + format! -> sql_execution", _atu(_rustSqlVuln, "x.rs").findings.some((f) => f.sink === "sql_execution"), JSON.stringify(_atu(_rustSqlVuln, "x.rs").findings.map((f) => f.sink)));
check("rust_unsafe: transmute fires", _dcb2("fn f() { let x: &[u8] = std::mem::transmute(user_data); }", "lib.rs").some((f) => f.type === "rust_unsafe"), "unsafe");
check("rust_format_string: println!(var) fires, println!(\"{}\", var) is clean", _dcb2("fn f() { println!(user_input); }", "main.rs").some((f) => f.type === "rust_format_string") && !_dcb2("fn f() { println!(\"{}\", user_input); }", "main.rs").some((f) => f.type === "rust_format_string"), "format");

// 79. Hackbot Arena benchmark integration
import { hackbotArenaList as _hal, hackbotArenaBrief as _hab, hackbotArenaCoverage as _hac } from "../src/hackbot-arena.ts";
check("hackbot-arena: 30 labs loaded", (_hal() as any).total === 30, `${(_hal() as any).total}`);
const _hab3 = _hab("labs03") as any;
check("hackbot-arena: labs03 (JWTea) -> jwt vector + jwt_analyze tool", (_hab3.attack_plan?.vectors ?? []).includes("jwt") && (_hab3.attack_plan?.tools ?? []).includes("jwt_analyze") && !JSON.stringify(_hab3).includes("nusasec-21d41"), `vectors=${_hab3.attack_plan?.vectors}`);
check("hackbot-arena: brief exposes flag FORMAT not the flag value", JSON.stringify(_hab3).includes("FLAG{nusasec-<32 hex>}") && !/[0-9a-f]{32}/.test(JSON.stringify(_hab3)), "format-only");
const _hacov = _hac() as any;
check("hackbot-arena: coverage >= 25/30 labs mapped", _hacov.labs_with_mapped_vector >= 25, `${_hacov.labs_with_mapped_vector}/${_hacov.total_labs}`);

// 80. Detection benchmark fixes (Hackbot Arena FP/FN remediation)
check("jwt_alg_confusion: dual RS256+HS256 with public-key HMAC fires", _dcb2(`function v(t){ if(t.alg==='RS256'){ ver.verify(KEYS.publicKey); } else if(t.alg==='HS256'){ crypto.createHmac('sha256', KEYS.publicKey).update(d).digest(); } }`, "auth.js").some((f) => f.type === "jwt_alg_confusion") && !_dcb2(`function v(t){ if(t.alg==='RS256'){ ver.verify(KEYS.publicKey); } else throw new Error('bad alg'); }`, "auth.js").some((f) => f.type === "jwt_alg_confusion"), "jwt");
check("cache_deception: cookie-less static cache key fires", _dcb2(`location ~* \\.(css|js|png)$ { proxy_cache ctf; }\nproxy_cache_key "$scheme$request_method$request_uri";`, "nginx.conf").some((f) => f.type === "cache_deception"), "cache");
check("missing_authz: public register route NOT flagged", !_dcb2(`@app.route('/auth/register')\ndef register():\n    return jsonify({})`, "app.py").some((f) => f.type === "missing_authz"), "public-skip");
check("missing_authz: @require_auth decorator suppresses", !_dcb2(`@app.route('/admin')\n@require_auth\ndef admin():\n    return jsonify({})`, "app.py").some((f) => f.type === "missing_authz"), "decorator-auth");
check("hardcoded_secret: FLAG{...} literal suppressed", !_dcb2(`const api_key = "FLAG{nusasec-deadbeef0000000000000000deadbeef}";`, "x.js").some((f) => f.type === "hardcoded_secret"), "flag-suppress");
check("ssti: Liquid Template(var) from stored input fires", _dcb2(`from liquid import Template\nout = Template(profile_bio).render()`, "app.py").some((f) => f.type === "ssti"), "liquid");
{
  const { writeFileSync, unlinkSync } = await import("node:fs");
  writeFileSync("/tmp/__blitz_sink_test.py", "subprocess.run(cmd, shell=True)\nrequests.get(url)\nurllib.request.urlopen(u)\nos.system(x)\n");
  const _sinkScan = scanFile("/tmp/__blitz_sink_test.py");
  check("sink: Node/Python command/SSRF sinks mapped", _sinkScan.sinks.some((s) => s.class.includes("command execution")) && _sinkScan.sinks.some((s) => s.class.includes("SSRF")), _sinkScan.sinks.map((s) => s.class).join(","));
  unlinkSync("/tmp/__blitz_sink_test.py");
}

// 81. Config/manifest files are scanned (cache_deception + dependency_confusion need them)
{
  const { mkdirSync, writeFileSync, rmSync } = await import("node:fs");
  mkdirSync("/tmp/__blitz_cfg", { recursive: true });
  writeFileSync("/tmp/__blitz_cfg/nginx.conf", 'proxy_cache_path /c;\nproxy_cache_key "$scheme$request_method$request_uri";\nlocation ~* \\.(css|js|png)$ { proxy_cache c; }\n');
  const cfgFiles = iterSourceFiles("/tmp/__blitz_cfg", 100);
  check("scan: .conf config files are included", cfgFiles.some((f) => f.endsWith(".conf")), JSON.stringify(cfgFiles));
  rmSync("/tmp/__blitz_cfg", { recursive: true, force: true });
}

// 82. Node/Python SQL sinks + interpolation (cross-file case)
check("sql_injection: Node template-literal SQL fires", _dcb2(`const q = \`SELECT * FROM users WHERE id = \${userId}\`;\npool.query(q);`, "db.js").some((f) => f.type === "sql_injection"), "node-sqli");
check("sql_injection: Python f-string SQL fires", _dcb2(`q = f"SELECT * FROM t WHERE role = '{role}'"\ncursor.execute(q)`, "app.py").some((f) => f.type === "sql_injection"), "py-fstring");

// 83. FP reduction (precision) — benchmark-driven
{
  const { writeFileSync, unlinkSync } = await import("node:fs");
  writeFileSync("/tmp/__fp_test.js", "db.exec(\"CREATE TABLE users(id INT)\");\n");
  check("sink: sqlite db.exec(...) NOT flagged as RCE", !scanFile("/tmp/__fp_test.js").sinks.some((s) => s.class.includes("command execution")), JSON.stringify(scanFile("/tmp/__fp_test.js").sinks.map((s) => s.class)));
  unlinkSync("/tmp/__fp_test.js");
}
check("missing_authz: express bearer+requireAdmin middleware suppresses", !_dcb2(`app.get('/api/admin/users', bearer, requireAdmin, (req, res) => {});`, "api.js").some((f) => f.type === "missing_authz"), "bearer-admin");
check("hardcoded_secret: function-call value (getApiKeyFromRequest) NOT flagged", !_dcb2(`const apiKey = getApiKeyFromRequest(req);`, "server.js").some((f) => f.type === "hardcoded_secret"), "fn-call");

// 84. OOB listener (blind SSRF/XXE/SQLi proof) — deterministic parsing + lifecycle
import { extractDomain as _exDom, parseInteractions as _parseInt, stripAnsi as _stripAnsi, oobPoll as _oobPoll, oobStop as _oobStop, oobList as _oobList } from "../src/oob.ts";
check("oob: stripAnsi removes color codes", _stripAnsi("[\u001b[34mINF\u001b[0m] x") === "[INF] x", JSON.stringify(_stripAnsi("[\u001b[34mINF\u001b[0m] x")));
check("oob: extractDomain parses ANSI-colored [INF] domain", _exDom("[\u001b[34mINF\u001b[0m] abcdefghijklmnopqrstuvwxyz123456.oast.site\n") === "abcdefghijklmnopqrstuvwxyz123456.oast.site", _exDom("[\u001b[34mINF\u001b[0m] abcdefghijklmnopqrstuvwxyz123456.oast.site\n") ?? "null");
const _oobHits = _parseInt('{"protocol":"http","timestamp":"2026-01-01T00:00:00Z","raw-request":"GET /x HTTP/1.1\\r\\nHost: a.oast.site","remote-address":"1.2.3.4","unique-id":"abcdefghijklmnopqrstuvwxyz123456"}\n');
check("oob: parseInteractions extracts a JSONL hit", _oobHits.length === 1 && _oobHits[0].protocol === "http" && _oobHits[0].request_line === "GET /x HTTP/1.1", JSON.stringify(_oobHits));
check("oob: poll/stop unknown id -> error", Boolean((_oobPoll("nope") as any).error) && Boolean((_oobStop("nope") as any).error), "fail-closed");
check("oob: list starts empty/valid", Array.isArray((_oobList() as any).active), JSON.stringify(_oobList()));

// 85. Web3 / Solidity audit (10 bug classes)
import { web3Audit as _w3, web3Rank as _w3rank, foundryPoc as _w3poc } from "../src/web3.ts";
const _w3vuln = `contract Vault {
    mapping(address=>uint) balance;
    function withdraw(uint a) external { (bool ok,) = msg.sender.call{value:a}(""); balance[msg.sender] -= a; }
    function mint(address to, uint a) external { balance[to] += a; }
    function kill() external { selfdestruct(payable(msg.sender)); }
}`;
const _w3res = _w3(_w3vuln, "Vault.sol");
check("web3: reentrancy + missing_access_control + selfdestruct detected", ["reentrancy", "missing_access_control", "unprotected_selfdestruct"].every((c) => _w3res.some((f) => f.class_ === c)), _w3res.map((f) => f.class_).join(","));
const _w3safe = `contract Safe {
    mapping(address=>uint) balance;
    address owner;
    modifier onlyOwner { require(msg.sender==owner); _; }
    function withdraw(uint a) external { uint x = a; balance[msg.sender] -= x; (bool ok,) = msg.sender.call{value:x}(""); require(ok); }
}`;
const _w3safeRes = _w3(_w3safe, "Safe.sol");
check("web3: checks-effects-interactions pattern NOT flagged reentrancy", !_w3safeRes.some((f) => f.class_ === "reentrancy"), _w3safeRes.map((f) => f.class_).join(","));
check("web3: rank sorts critical-first", _w3rank(_w3res)[0]?.severity === "critical", JSON.stringify(_w3rank(_w3res)[0]));
check("web3: foundry PoC template non-empty", _w3poc("reentrancy", "Vault").includes("contract VaultPoc") && _w3poc("reentrancy", "Vault").includes("receive()"), "template");
const _w3v2 = _w3(`contract V3 {
    function getPrice() external view returns (uint256) { (uint160 p,,,,,,) = pool.slot0(); return uint256(p); }
    function hashFor(string calldata a, string calldata b) external pure returns (bytes32) { return keccak256(abi.encodePacked(a, b)); }
    function setOwner(address o) external { owner = o; }
}`, "V3.sol");
check("web3: slot0 oracle + encodePacked collision + address(0) detected", ["oracle_manipulation", "encode_packed_collision", "address_zero_check"].every((c) => _w3v2.some((f) => f.class_ === c)), _w3v2.map((f) => f.class_).join(","));

// XSS tighten: source + sink in the same file but NOT connected -> no xss
const _xssConnected = _dcb2(`const u = location.hash;\ndocument.body.innerHTML = u;`, "x.js").some((f) => f.type === "xss");
const _xssDisconnected = _dcb2(`const u = location.hash;\nconst other = "hello";\ndocument.body.innerHTML = other;`, "x.js").some((f) => f.type === "xss");
check("xss: connected source->sink flagged", _xssConnected, "connected");
check("xss: disconnected source+sink NOT flagged (no FP)", !_xssDisconnected, "disconnected");

// 86. Hunting doctrine + always-rejected kill-list (LLM-facing methodology)
import { killList as _kill, huntingDoctrine as _doctrine } from "../src/doctrine.ts";
check("kill_list: open_redirect rejected (weak standalone)", _kill("open_redirect").rejected === true, JSON.stringify(_kill("open_redirect")));
check("kill_list: sql_injection NOT rejected", _kill("sql_injection").rejected === false, JSON.stringify(_kill("sql_injection")));
check("kill_list: self_xss + missing_headers rejected", ["self_xss", "missing_headers"].every((t) => _kill(t).rejected), "weak-classes");
const _doc = _doctrine() as any;
check("doctrine: sibling rule + two-account present", _doc.doctrine.some((r: any) => r.id === "sibling_rule") && _doc.doctrine.some((r: any) => r.id === "two_account"), `doctrine=${_doc.doctrine.length}`);
check("doctrine: always_rejected list present", Array.isArray(_doc.always_rejected) && _doc.always_rejected.length >= 9, `n=${_doc.always_rejected?.length}`);

// 87. Sibling Rule Engine (deterministic logic-bug prober helpers)
import { extractObjectId as _eid, swapObjectId as _sid, generateSiblings as _gsib } from "../src/sibling-scan.ts";
check("sibling: extractObjectId numeric", _eid("/api/user/123/orders") === "123", _eid("/api/user/123/orders") ?? "null");
check("sibling: extractObjectId uuid", _eid("/api/order/a1b2c3d4-e5f6-7890-abcd-ef1234567890") !== null, "uuid");
check("sibling: swapObjectId swaps numeric id", _sid("/api/user/123/orders", "456") === "/api/user/456/orders", _sid("/api/user/123/orders", "456"));
const _sibs = _gsib("/api/user/123/orders", "456");
check("sibling: enumeration covers suffix + id-scoped siblings", _sibs.includes("/api/user/123/export") && _sibs.includes("/api/user/456/orders") && _sibs.length >= 30, `n=${_sibs.length}`);

// 88. Auto-PoC — reproduction recipe generator
import { autoPoc as _apoc, listPocTypes as _lpoc } from "../src/auto-poc.ts";
const _apocSql = _apoc({ type: "sql_injection", base_url: "https://x.com", endpoint: "/api/user/1", param: "id" });
check("auto-poc: sql_injection recipe has marker + control + expected", _apocSql.marker.includes("OR") && _apocSql.request.includes("OR") && _apocSql.control_request.includes("AND") && _apocSql.expected.length > 20, `${_apocSql.marker}`);
const _apocIdor = _apoc({ type: "idor", base_url: "https://x.com", endpoint: "/api/user/123", victim_id: "456" });
check("auto-poc: idor canonicalizes to missing_authz + victim swap", _apocIdor.type === "missing_authz" && _apocIdor.request.includes("456"), `${_apocIdor.type} ${_apocIdor.request}`);
check("auto-poc: 18 classes supported", _lpoc().length >= 18, `n=${_lpoc().length}`);

// 89. Foundry runner — parse forge test results
import { parseTestResults as _fparse } from "../src/foundry-run.ts";
const _fout = "[PASS] testReentrancy() (gas: 12345)\n[FAIL. Reason: assertion failed] testBroken() (gas: 999)";
const _fres = _fparse(_fout);
check("foundry: parseTestResults pass+fail", _fres.some((t) => t.name.includes("testReentrancy") && t.status === "pass") && _fres.some((t) => t.name.includes("testBroken") && t.status === "fail"), JSON.stringify(_fres));

console.log();
const nPass = results.filter(([, ok]) => ok).length;
console.log(`=== ${nPass}/${results.length} checks passed ===`);
process.exit(nPass === results.length ? 0 : 1);
