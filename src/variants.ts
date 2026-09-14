/** Variant corpus scanner — sweep every real-world code shape against its class's
 *  detector and report per-class coverage.
 *
 *  The variant corpus (intelligence/variants.json) is a set of concrete code
 *  shapes, each of which MUST fire its class's detector. This scanner runs the
 *  detectors against every shape and surfaces false negatives — a detector that
 *  misses a real shape is a coverage gap, not something to paper over. This is
 *  how the empirical grounding scales: more shapes → more coverage, tested
 *  reproducibly.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { detectComplexBugs } from "./complex-bugs.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface Variant {
  class: string;
  code: string;
  note: string;
  /** Optional file name/extension so manifest-gated detectors (dependency_confusion)
   *  get the right context (e.g. "requirements.txt", "package.json"). */
  file?: string;
}

function loadVariants(): Variant[] {
  try {
    const doc = JSON.parse(readFileSync(join(__dirname, "..", "intelligence", "variants.json"), "utf8")) as { variants?: Variant[] };
    return doc.variants ?? [];
  } catch {
    return [];
  }
}

export interface VariantResult {
  id: string;
  class: string;
  fired: boolean;
  note: string;
}

export interface VariantCoverage {
  total: number;
  fired: number;
  missed: number;
  coverage: number;
  per_class: Record<string, { total: number; fired: number; missed: number; coverage: number }>;
  results: VariantResult[];
}

/** The cross-file `priv_esc` detector needs a file tree, so its shapes are
 *  verified separately (verification corpus + cross-file regression), not here. */
const CROSS_FILE_ONLY = new Set(["priv_esc"]);

export function scanVariants(): VariantCoverage {
  const variants = loadVariants().filter((v) => !CROSS_FILE_ONLY.has(v.class));
  const results: VariantResult[] = variants.map((v, i) => {
    const findings = detectComplexBugs(v.code, v.file ?? `variant-${i}.php`).filter((f) => f.type === v.class);
    return { id: `variant-${i}`, class: v.class, fired: findings.length > 0, note: v.note };
  });

  const per_class: Record<string, { total: number; fired: number; missed: number; coverage: number }> = {};
  for (const r of results) {
    const c = (per_class[r.class] ??= { total: 0, fired: 0, missed: 0, coverage: 0 });
    c.total++;
    if (r.fired) c.fired++;
    else c.missed++;
    c.coverage = c.fired / c.total;
  }

  const fired = results.filter((r) => r.fired).length;
  return {
    total: results.length,
    fired,
    missed: results.length - fired,
    coverage: results.length > 0 ? fired / results.length : 0,
    per_class,
    results,
  };
}

export function variantCoverageText(): string {
  const r = scanVariants();
  const lines: string[] = [];
  lines.push(`Blitz Strike variant corpus`);
  lines.push(`  ${r.fired}/${r.total} shapes detected (${(r.coverage * 100).toFixed(0)}%) · ${r.missed} missed`);
  lines.push(``);
  for (const [cls, c] of Object.entries(r.per_class)) {
    const mark = c.missed === 0 ? "OK " : "GAP";
    lines.push(`  [${mark}] ${cls.padEnd(20)} ${c.fired}/${c.total}`);
  }
  if (r.missed > 0) {
    lines.push(``);
    for (const res of r.results.filter((x) => !x.fired)) {
      lines.push(`  missed: ${res.class} — ${res.note}`);
    }
  }
  return lines.join("\n");
}
