// Benchmark harness #2 — 10 more complex/core WordPress plugins (blind scan).
import { variantScan } from "../src/variant-scan.ts";
import { readdirSync } from "node:fs";
import { join } from "node:path";

const base = join(process.cwd(), "bench", "plugins-bench2");
const plugins = readdirSync(base, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

for (const p of plugins) {
  const root = join(base, p);
  const t0 = Date.now();
  const r = variantScan(root) as {
    files_scanned: number; total_findings: number;
    hits: Array<{ file: string; detector: string; type: string; line: number; severity: string }>;
  };
  const ms = Date.now() - t0;

  // High-signal findings (skip route_confusion noise) grouped by type.
  const byType: Record<string, Array<{ file: string; line: number }>> = {};
  for (const h of r.hits) {
    if (h.detector === "route_confusion") continue;
    (byType[h.type] ??= []).push({ file: h.file.replace(root + "/", ""), line: h.line });
  }

  console.log(`\n=== ${p} ===  (${r.files_scanned} files, ${r.total_findings} total, ${ms}ms)`);
  for (const [type, locs] of Object.entries(byType)) {
    console.log(`  [${type}] x${locs.length}`);
    for (const l of locs.slice(0, 2)) console.log(`      ${l.file}:${l.line}`);
  }
}
