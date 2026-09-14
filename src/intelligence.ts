/** Empirical Intelligence Ledger — the enterprise layer that makes Blitz Strike
 *  COMPOUND across engagements.
 *
 *  Every VERIFIED verdict (confirmed / false_positive) is recorded as a
 *  (vector, tech) outcome. Hit-rates feed a Bayesian posterior that upgrades
 *  attack_plan's relevance prior into an EMPIRICAL prior. Cross-target: a new
 *  target with the same tech inherits the historical hit-rates.
 *
 *  Design rules (same as memory.ts):
 *   - Append-only JSONL (never corrupts, no lost writes).
 *   - Dedup by stable hash (vector + tech + target + outcome).
 *   - Only VERIFIED verdicts enter the ledger (hypotheses never do).
 *
 *  Location: $BLITZSTRIKE_HOME/intelligence.jsonl (default ~/.blitzstrike/).
 */
import { readFileSync, appendFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";

const HOME_DIR = process.env.BLITZSTRIKE_HOME ?? join(homedir(), ".blitzstrike");
const INTEL_PATH = join(HOME_DIR, "intelligence.jsonl");

export type VerdictOutcome = "confirmed" | "false_positive";

export interface IntelEntry {
  id: string;
  vector: string;
  tech: string;
  framework?: string;
  severity?: string;
  outcome: VerdictOutcome;
  target?: string;
  cvss?: number;
  ts: string;
  dedup_hash: string;
}

/** Map a finding sink type -> attack-vector name (so the ledger + attack_plan share one namespace). */
const SINK_TO_VECTOR: Record<string, string> = {
  sql_execution: "sql_injection",
  command_execution: "command_injection",
  html_render: "xss",
  code_execution: "code_execution",
  http_request: "ssrf",
  deserialization: "deserialization",
  file_operations: "path_traversal",
  file_inclusion: "path_traversal",
  template_injection: "ssti",
  xml_processing: "xxe",
  path_traversal: "path_traversal",
  redirect: "open_redirect",
  auth_bypass: "auth_bypass",
  cors_misconfiguration: "cors_misconfiguration",
};

export function sinkToVector(sinkType: string): string {
  return SINK_TO_VECTOR[sinkType.toLowerCase()] ?? sinkType.toLowerCase();
}

function ensureDir(): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
}

function dedupHash(vector: string, tech: string, target: string, outcome: string): string {
  return createHash("sha256").update(`${vector}\u0000${tech}\u0000${target}\u0000${outcome}`).digest("hex").slice(0, 16);
}

export function loadIntel(): IntelEntry[] {
  if (!existsSync(INTEL_PATH)) return [];
  try {
    const out: IntelEntry[] = [];
    for (const line of readFileSync(INTEL_PATH, "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t) as IntelEntry);
      } catch {
        /* skip corrupt line */
      }
    }
    return out;
  } catch {
    return [];
  }
}

function append(entry: IntelEntry): void {
  ensureDir();
  appendFileSync(INTEL_PATH, JSON.stringify(entry) + "\n");
}

/** Record a VERIFIED verdict. Dedup by (vector, tech, target, outcome). */
export function recordVerdict(input: {
  vector: string;
  tech?: string;
  framework?: string;
  severity?: string;
  outcome: VerdictOutcome;
  target?: string;
  cvss?: number;
}): Record<string, unknown> {
  const vector = input.vector.trim().toLowerCase();
  const tech = (input.tech ?? "unknown").trim().toLowerCase();
  const target = (input.target ?? "").trim();
  const hash = dedupHash(vector, tech, target, input.outcome);
  const existing = loadIntel().find((e) => e.dedup_hash === hash);
  if (existing) {
    return { saved: false, duplicate: true, id: existing.id, vector, tech, outcome: input.outcome };
  }
  const entry: IntelEntry = {
    id: `int-${hash.slice(0, 12)}`,
    vector,
    tech,
    framework: input.framework,
    severity: input.severity,
    outcome: input.outcome,
    target: target || undefined,
    cvss: input.cvss,
    ts: new Date().toISOString(),
    dedup_hash: hash,
  };
  append(entry);
  return { saved: true, duplicate: false, id: entry.id, vector, tech, outcome: input.outcome };
}

interface HitRate {
  vector: string;
  tech: string;
  tested: number;
  confirmed: number;
  false_positive: number;
  hit_rate: number;
}

/** Aggregate hit-rates per (vector, tech). Optionally filter by tech. */
export function hitRates(tech?: string): Record<string, unknown> {
  const entries = loadIntel();
  const filtered = tech ? entries.filter((e) => e.tech === tech.toLowerCase()) : entries;
  const agg = new Map<string, HitRate>();
  for (const e of filtered) {
    const key = `${e.vector}\u0000${e.tech}`;
    const a = agg.get(key) ?? { vector: e.vector, tech: e.tech, tested: 0, confirmed: 0, false_positive: 0, hit_rate: 0 };
    a.tested += 1;
    if (e.outcome === "confirmed") a.confirmed += 1;
    else a.false_positive += 1;
    agg.set(key, a);
  }
  const list = [...agg.values()].map((a) => ({ ...a, hit_rate: Number((a.confirmed / a.tested).toFixed(3)) }));
  list.sort((x, y) => y.hit_rate - x.hit_rate || y.tested - x.tested);
  return { tech: tech ?? null, total_verdicts: filtered.length, entries: list };
}

/** Bayesian posterior that upgrades the formula prior with empirical (confirmed, tested).
 *  Beta-binomial smoothing with prior strength K=5. Falls back from (vector,tech)
 *  -> (vector, any-tech) -> formula prior. */
export function empiricalPrior(vector: string, tech: string, formulaPrior: number): number {
  const v = vector.toLowerCase();
  const t = (tech || "unknown").toLowerCase();
  const all = loadIntel();
  const specific = all.filter((e) => e.vector === v && e.tech === t);
  const pool = specific.length > 0 ? specific : all.filter((e) => e.vector === v);
  if (pool.length === 0) return formulaPrior;
  const confirmed = pool.filter((e) => e.outcome === "confirmed").length;
  const tested = pool.length;
  const K = 5; // prior strength in pseudo-observations
  const alpha = formulaPrior * K;
  const beta = (1 - formulaPrior) * K;
  const posterior = (confirmed + alpha) / (tested + alpha + beta);
  return Math.round(posterior * 100) / 100;
}

/** Rank vectors by empirical hit-rate for a tech (only vectors with a confirmed hit). */
export function topVectors(tech: string, limit = 10): Record<string, unknown> {
  const rates = hitRates(tech);
  const entries = (rates.entries as HitRate[]).filter((e) => e.hit_rate > 0);
  return { tech, top: entries.slice(0, limit) };
}

/** Search the ledger. */
export function queryIntel(filter: { vector?: string; tech?: string; outcome?: string } = {}): Record<string, unknown> {
  let entries = loadIntel();
  if (filter.vector) entries = entries.filter((e) => e.vector === filter.vector!.toLowerCase());
  if (filter.tech) entries = entries.filter((e) => e.tech === filter.tech!.toLowerCase());
  if (filter.outcome) entries = entries.filter((e) => e.outcome === filter.outcome);
  entries.sort((a, b) => (a.ts < b.ts ? 1 : -1));
  return {
    total: entries.length,
    entries: entries.slice(0, 50).map((e) => ({
      id: e.id, vector: e.vector, tech: e.tech, framework: e.framework, severity: e.severity,
      outcome: e.outcome, target: e.target, cvss: e.cvss, ts: e.ts,
    })),
  };
}
