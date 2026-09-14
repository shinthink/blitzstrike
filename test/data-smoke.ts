// Comprehensive data-layer smoke test — loads EVERY data file the MCP tools
// read at runtime and reports pass/fail with counts.
import { loadChains } from "../src/orchestrator.ts";
import { loadManualIndex, listManuals, findManual, readPlaybook, listPlaybooks } from "../src/manuals.ts";
import { listFrameworks, frameworkProfile } from "../src/frameworks.ts";
import { loadTools, loadSkills, listTools, listSkills, readSkill } from "../src/catalog.ts";
import {
  listPayloadCategories, payloadLookup, listAttackVectors, techniqueLookup,
  frameworkTricks, resourceLookup, taxonomy, bypassLookup, chainLinks,
  retryGuidance, modelFallback, detectWaf, techCorrelation, cveCorrelation,
  portCorrelation, intelSummary, orchestration, abSignal, listAbSignalClasses,
  listCveChains, cveChain,
  listAppPlaybooks, appPlaybook,
} from "../src/intel.ts";

const results: Array<[string, boolean, string]> = [];
function check(name: string, ok: boolean, detail = "") {
  results.push([name, ok, detail]);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ${detail}`);
}

// 1) chains
const chains = loadChains();
check("chains.json", chains.length > 0, `${chains.length} chains`);

// 2) manuals + playbooks
const mi = loadManualIndex();
const lm = listManuals() as any;
check("manuals-index.json", Object.keys(mi.tools).length > 0, `${Object.keys(mi.tools).length} manuals indexed`);
const fm = findManual("nmap") as any;
check("findManual(nmap)", fm && fm.content && fm.content.length > 100, `content=${(fm?.content ?? "").length} chars`);
check("listManuals", lm && lm.total_tools > 0, `total_tools=${lm?.total_tools}`);
const pb = readPlaybook("web-application") as any;
check("readPlaybook(web-application)", pb?.found === true, `content=${pb?.content?.length ?? 0}`);
const lp = listPlaybooks() as any;
check("listPlaybooks", lp && (lp.total_playbooks ?? lp.playbooks?.length ?? 0) >= 17, JSON.stringify(lp).slice(0, 80));

// 3) frameworks
const fw = listFrameworks();
check("frameworks.json", fw.length > 0, `${fw.length} frameworks`);
const wpProfile = frameworkProfile("wordpress");
check("wordpress P1-P6 vuln patterns", (wpProfile?.patterns?.length ?? 0) === 6, `${wpProfile?.patterns?.length ?? 0} patterns`);

// ab-signals (finding -> next-action knowledge base)
const abClasses = listAbSignalClasses() as { classes: unknown[] };
check("ab-signals: >=16 vuln classes", (abClasses.classes?.length ?? 0) >= 16, `${abClasses.classes?.length ?? 0} classes`);
const abSqli = abSignal("sqli") as Record<string, unknown>;
check("ab-signals: sqli lookup has proof_oracle + kill_conditions", abSqli.found === true && typeof abSqli.proof_oracle === "string" && Array.isArray(abSqli.kill_conditions), `${abSqli.proof_oracle}`);

// cve-chains (high-impact RCE/unauth verify chains)
const cvc = listCveChains() as { count: number; chains: unknown[] };
check("cve-chains: >=14 curated high-impact chains", (cvc.chains?.length ?? 0) >= 14, `${cvc.chains?.length ?? 0} chains`);
const cveLog4 = cveChain("CVE-2021-44228") as Record<string, unknown>;
check("cve-chains: log4shell lookup has verify_chain + proof_oracle + negative_control", cveLog4.found === true && cveLog4.proof_oracle === "oob" && Array.isArray(cveLog4.verify_chain) && (cveLog4.verify_chain as unknown[]).length >= 1, `${cveLog4.proof_oracle}`);
const cveByName = cveChain("log4shell") as Record<string, unknown>;
check("cve-chains: lookup by name/product", cveByName.found === true && (cveByName.cve as string[]).includes("CVE-2021-44228"), "name lookup");

// app-playbooks (live-verified lab-app vuln chains)
const apl = listAppPlaybooks() as { count: number; apps: unknown[] };
check("app-playbooks: >=6 lab apps", (apl.apps?.length ?? 0) >= 6, `${apl.apps?.length ?? 0} apps`);
const apVampi = appPlaybook("vampi") as Record<string, unknown>;
check("app-playbooks: vampi has vulns with steps + proof_oracle", apVampi.found === true && Array.isArray(apVampi.vulns) && (apVampi.vulns as unknown[]).length >= 2 && ((apVampi.vulns as Array<{ steps: unknown[]; proof_oracle: string }>)[0].steps.length >= 1 && typeof (apVampi.vulns as Array<{ proof_oracle: string }>)[0].proof_oracle === "string"), `${(apVampi.vulns as unknown[]).length} vulns`);
const apIdor = appPlaybook("idor") as Record<string, unknown>;
check("app-playbooks: lookup by vuln_class returns matching apps", apIdor.found === true && Array.isArray(apIdor.apps) && (apIdor.apps as unknown[]).length >= 2, `matched_by=${apIdor.matched_by}`);

// 4) tools-catalog + skills
const tools = loadTools();
check("tools-catalog.json", tools.length > 100, `${tools.length} tools`);
const skills = loadSkills();
check("skills (catalog load)", skills.length > 30, `${skills.length} skills`);
const rs = readSkill("bs-orchestrate-engagement") as any;
check("readSkill(bs-orchestrate-engagement)", rs && rs.found === true, `found=${rs?.found}`);

// 5) payloads
const pc = listPayloadCategories();
check("payloads (data cache)", pc.length >= 60, `${pc.length} categories`);
check("payloadLookup(sql injection)", payloadLookup("sql injection") !== undefined, "");

// 6) intelligence data
check("techniqueLookup(xss)", (techniqueLookup("xss") as any)?.techniques?.length > 0, "");
check("frameworkTricks(laravel)", (frameworkTricks("laravel") as any)?.tricks?.length > 0, "");
check("resourceLookup(web)", (resourceLookup("web") as any)?.found === true, "");
check("taxonomy(cwe,ssrf)", (taxonomy("cwe", "ssrf") as any) !== undefined, "");
check("taxonomy(owasp, A01)", (taxonomy("owasp", "A01") as any) !== undefined, "");
check("taxonomy(api, API1)", (taxonomy("api", "API1") as any) !== undefined, "");
check("taxonomy(asvs, V1)", (taxonomy("asvs", "V1") as any) !== undefined, "");
check("listAttackVectors", (listAttackVectors() as any)?.total_vectors > 500, "");
check("bypassLookup(waf)", bypassLookup("waf") !== undefined, "");
check("chainLinks", chainLinks("ssrf_cloud_metadata") !== undefined, "");
check("retryGuidance", retryGuidance("429") !== undefined, "");
check("modelFallback", modelFallback("rate_limit") !== undefined, "");
check("detectWaf", detectWaf("cloudflare") !== undefined, "");
check("techCorrelation(laravel)", techCorrelation("laravel") !== undefined, "");
check("cveCorrelation(CVE-2021-44228)", cveCorrelation("CVE-2021-44228") !== undefined, "");
check("portCorrelation(80)", portCorrelation(80) !== undefined, "");
const isum = intelSummary() as any;
check("intelSummary", isum?.waf_signatures > 100 && isum?.tech_correlations > 50, `waf=${isum?.waf_signatures} tech=${isum?.tech_correlations}`);
check("orchestration", orchestration() !== undefined, "");

console.log("\n" + "=".repeat(70));
const fails = results.filter(([, ok]) => !ok);
console.log(`TOTAL: ${results.length - fails.length}/${results.length} PASS`);
if (fails.length) {
  console.log("FAILURES:");
  for (const [n, , d] of fails) console.log(`  - ${n}: ${d}`);
}
