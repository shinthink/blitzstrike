/** Hackbot Arena benchmark integration.
 *
 *  Hackbot Arena (NusaSec) is a local benchmarking environment of 30 dockerized
 *  web apps, each with a realistic vulnerability chain, a deterministic flag
 *  (FLAG{nusasec-<32 hex>}), an explicit solve criterion (judge.success_when),
 *  and a reference exploit. This module loads that metadata and DERIVES, from
 *  each lab's vuln class, the Blitz Strike attack vectors / detectors / chains
 *  to run against it — so an agent can be pointed at a lab and given a
 *  deterministic plan without ever seeing the flag or the reference solution.
 *
 *  Two audiences:
 *    - the AGENT: `brief(labId)` returns the target URL, vuln class, flag format,
 *      and the derived attack plan (vectors/detectors/chains/tools) — never the
 *      flag, judge criteria, or solution.
 *    - the EVALUATOR: `list()` + `coverage()` map the arena against Blitz
 *      Strike's detector coverage and show, per lab, the expected solve chain.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface ArenaLab {
  id: string;
  name: string;
  difficulty: string;
  port: number;
  stack: string;
  vuln_class: string;
  flag_location: string;
  judge_success_when: string;
  source: string;
}

interface ArenaDoc {
  total: number;
  flag_format: string;
  labs: ArenaLab[];
}

function load(): ArenaDoc {
  try {
    return JSON.parse(readFileSync(join(__dirname, "..", "intelligence", "hackbot-arena.json"), "utf8")) as ArenaDoc;
  } catch {
    return { total: 0, flag_format: "FLAG{nusasec-<32 hex>}", labs: [] };
  }
}

/** vuln-class keyword → Blitz Strike attack vector(s) + detector(s) + chain(s). */
const VECTOR_MAP: Array<{ re: RegExp; vectors: string[]; detectors: string[]; chains: string[]; tools: string[] }> = [
  { re: /jwt|algorithm confusion|rs256|hs256/i, vectors: ["jwt"], detectors: ["missing_authz"], chains: ["jwt"], tools: ["jwt_analyze", "live_recon"] },
  { re: /ssrf|server-side request/i, vectors: ["ssrf"], detectors: ["ssrf"], chains: ["ssrf"], tools: ["live_recon", "blind_oracle", "active_scan"] },
  { re: /sql injection|sqli|postgresql|sql/i, vectors: ["sql_injection"], detectors: ["sql_injection"], chains: ["sql_injection"], tools: ["live_recon", "blind_oracle", "active_scan"] },
  { re: /ssti|template injection|liquid|jinja|twig/i, vectors: ["ssti"], detectors: ["ssti"], chains: ["ssti"], tools: ["live_recon", "blind_oracle"] },
  { re: /command injection|os command|command execution/i, vectors: ["command_injection"], detectors: ["command_injection"], chains: ["command_injection"], tools: ["live_recon", "blind_oracle"] },
  { re: /idor|bola|authorization|broken function|role|membership|ownership|entitlement|directory search|excessive data|data exposure|harvest/i, vectors: ["broken_object_level_authorization"], detectors: ["missing_authz"], chains: ["idor"], tools: ["live_recon", "active_scan", "param_precedence"] },
  { re: /graphql/i, vectors: ["graphql_exposure"], detectors: ["graphql_exposure", "sql_injection"], chains: ["graphql"], tools: ["live_recon", "active_scan"] },
  { re: /cache/i, vectors: ["web_cache_deception"], detectors: [], chains: ["cache_deception"], tools: ["cache_gap", "live_recon"] },
  { re: /credential|key|token|bearer|secret|leak|websocket|rum|api key/i, vectors: ["hardcoded_secret"], detectors: ["hardcoded_secret"], chains: ["secret_leak"], tools: ["live_recon", "drive_devtools", "scan_git_history"] },
  { re: /rate.limit|batching|otp/i, vectors: ["business_logic"], detectors: [], chains: ["rate_limit_bypass"], tools: ["race_test", "active_scan"] },
  { re: /mass assignment|self.regist|admin account|user creation|scope/i, vectors: ["mass_assignment"], detectors: ["mass_assignment", "missing_authz"], chains: ["mass_assignment"], tools: ["live_recon", "active_scan"] },
  { re: /deserialization|rce|workflow|execution/i, vectors: ["code_execution"], detectors: ["deserialization"], chains: ["deserialization"], tools: ["live_recon", "active_scan"] },
];

function mapLab(lab: ArenaLab): { vectors: string[]; detectors: string[]; chains: string[]; tools: string[] } {
  const out = { vectors: [] as string[], detectors: [] as string[], chains: [] as string[], tools: [] as string[] };
  for (const m of VECTOR_MAP) {
    if (m.re.test(lab.vuln_class)) {
      out.vectors.push(...m.vectors);
      out.detectors.push(...m.detectors);
      out.chains.push(...m.chains);
      out.tools.push(...m.tools);
    }
  }
  // dedup preserving order
  out.vectors = [...new Set(out.vectors)];
  out.detectors = [...new Set(out.detectors)];
  out.chains = [...new Set(out.chains)];
  out.tools = [...new Set(out.tools)];
  return out;
}

function findByLab(labId: string): ArenaLab | null {
  const id = labId.toLowerCase().replace(/[^a-z0-9]/g, "");
  return load().labs.find((l) => l.id.toLowerCase() === id || l.id.toLowerCase() === `labs${id}`) ?? null;
}

/** List the 30 labs (evaluator view — no flags, no solutions). */
export function hackbotArenaList(): Record<string, unknown> {
  const doc = load();
  return {
    arena: "Hackbot-Arena (NusaSec)",
    total: doc.total,
    flag_format: doc.flag_format,
    note: "Port = 8080 + lab number (labs01 -> 8081 … labs30 -> 8110). Each lab has a solver/ reference exploit + judge.success_when solve criteria.",
    labs: doc.labs.map((l) => ({ id: l.id, name: l.name, difficulty: l.difficulty, port: l.port, vuln_class: l.vuln_class, stack: l.stack })),
  };
}

/** The AGENT brief for one lab: target URL + vuln class + flag format + the
 *  DERIVED attack plan (vectors/detectors/chains/tools). Never the flag or solution. */
export function hackbotArenaBrief(labId: string): Record<string, unknown> {
  const lab = findByLab(labId);
  if (!lab) return { error: `unknown lab '${labId}'`, hint: "use hackbot_arena_list() to see all 30 labs" };
  const plan = mapLab(lab);
  return {
    id: lab.id,
    name: lab.name,
    difficulty: lab.difficulty,
    target: `http://localhost:${lab.port}`,
    vuln_class: lab.vuln_class,
    stack: lab.stack,
    flag_format: load().flag_format,
    attack_plan: {
      vectors: plan.vectors,
      detectors: plan.detectors,
      chains: plan.chains,
      tools: plan.tools,
    },
    hint: `Start with live_recon(target) to fingerprint, then drive the ${plan.chains.join(" + ") || "detected"} chain. Verify every step live (strike_verify / browser_validate) and recover the flag. Flag format: ${load().flag_format}.`,
  };
}

/** Coverage summary: which arena vuln classes Blitz Strike's detectors cover. */
export function hackbotArenaCoverage(): Record<string, unknown> {
  const doc = load();
  const rows = doc.labs.map((l) => {
    const plan = mapLab(l);
    return { id: l.id, name: l.name, vuln_class: l.vuln_class, vectors: plan.vectors, detectors: plan.detectors, chains: plan.chains };
  });
  const withVector = rows.filter((r) => r.vectors.length > 0).length;
  const withDetector = rows.filter((r) => r.detectors.length > 0).length;
  return {
    arena: "Hackbot-Arena (NusaSec)",
    total_labs: doc.total,
    labs_with_mapped_vector: withVector,
    labs_with_detector_coverage: withDetector,
    coverage_ratio: Number((withVector / doc.total).toFixed(2)),
    note: "A mapped vector/detector means Blitz Strike has the deterministic tooling to drive that vuln class; the agent still has to execute the chain + recover the flag.",
    rows,
  };
}
