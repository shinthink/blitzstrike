// Benchmark harness: run the full detector stack (variantScan = taint +
// complex_bugs + route_confusion) blind over 10 real vulnerable WordPress
// plugins. No hints — just point at the directory and report the hits.
import { variantScan } from "../src/variant-scan.ts";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const base = join(process.cwd(), "bench", "plugins-bench");
const plugins = readdirSync(base, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const report: Array<Record<string, unknown>> = [];

for (const p of plugins) {
  const root = join(base, p);
  if (!statSync(root).isDirectory()) continue;
  const t0 = Date.now();
  const r = variantScan(root) as {
    files_scanned: number; total_findings: number; files_with_findings: number;
    by_signature: Record<string, number>; hits: Array<{ file: string; detector: string; type: string; signature: string; line: number; severity: string }>;
  };
  const ms = Date.now() - t0;

  // Group hits by signature with a few example locations.
  const bySig: Record<string, Array<{ file: string; line: number }>> = {};
  for (const h of r.hits) (bySig[h.signature] ??= []).push({ file: h.file.replace(root + "/", ""), line: h.line });

  console.log(`\n=== ${p} ===`);
  console.log(`  files: ${r.files_scanned} | findings: ${r.total_findings} | files_with_findings: ${r.files_with_findings} | ${ms}ms`);
  for (const [sig, locs] of Object.entries(bySig)) {
    console.log(`  [${sig}] x${locs.length}`);
    for (const l of locs.slice(0, 2)) console.log(`      ${l.file}:${l.line}`);
  }

  report.push({ plugin: p, files_scanned: r.files_scanned, total_findings: r.total_findings, files_with_findings: r.files_with_findings, by_signature: r.by_signature, ms });
}

console.log("\n\n=== SUMMARY ===");
for (const r of report) console.log(`${String(r.plugin).padEnd(24)} files=${String(r.files_scanned).padStart(4)}  findings=${String(r.total_findings).padStart(3)}  signatures=${Object.keys(r.by_signature as Record<string, number>).length}`);
