/** Variant Mining — the "confirm once, weaponize everywhere" capability.
 *
 *  Given a confirmed bug in ONE source file, extract its SIGNATURE (a derived
 *  bug-family id) and mass-scan an entire install base for VARIANTS of the same
 *  bug. This is what turns a single CVE into hundreds: find the pattern once,
 *  then sweep 10k+ files for the same shape.
 *
 *  Deterministic + streaming: walks the tree via iterSourceFiles (capped),
 *  runs every detector per file, and reports hits-only grouped by signature.
 *  The signature is DERIVED (`<detector>:<type>`), never hardcoded.
 */
import { readFileSync } from "node:fs";
import { iterSourceFiles } from "./scanner.js";
import { detectComplexBugs } from "./complex-bugs.js";
import { detectRouteConfusion } from "./route-confusion.js";
import { analyzeTaint } from "./taint.js";
import { detectCrossFilePrivesc } from "./cross-file.js";

export interface VariantHit {
  file: string;
  detector: "taint" | "complex_bugs" | "route_confusion" | "cross_file";
  type: string;
  signature: string;
  line: number;
  severity: string;
  evidence: string;
}

/** Derive a bug-family signature from a detector + type. */
export function deriveSignature(detector: string, type: string): string {
  return `${detector}:${type}`;
}

export interface VariantScanOptions {
  maxFiles?: number;
  /** Mine for a SPECIFIC bug family (e.g. "complex_bugs:missing_authz"). */
  signature?: string;
}

export function variantScan(root: string, opts: VariantScanOptions = {}): Record<string, unknown> {
  const files = iterSourceFiles(root, opts.maxFiles ?? 5000);
  const hits: VariantHit[] = [];

  for (const file of files) {
    let code: string;
    try {
      code = readFileSync(file, "utf8");
    } catch {
      continue;
    }

    // Taint (source→sink).
    try {
      const taint = analyzeTaint(file);
      for (const f of taint.findings) {
        const type = f.category ?? f.sink ?? "taint";
        hits.push({
          file, detector: "taint", type,
          signature: deriveSignature("taint", type),
          line: f.sink_line ?? 0,
          severity: "high",
          evidence: f.sink ?? "",
        });
      }
    } catch {
      /* taint is best-effort per file */
    }

    // Complex bugs (deserialization, type juggling, mass assignment, SSRF, XXE,
    // SSTI, wrong-context sanitization, missing authz/nonce).
    for (const f of detectComplexBugs(code, file)) {
      hits.push({
        file, detector: "complex_bugs", type: f.type,
        signature: deriveSignature("complex_bugs", f.type),
        line: f.line, severity: f.severity, evidence: f.evidence,
      });
    }

    // Route confusion.
    for (const f of detectRouteConfusion(code, file)) {
      hits.push({
        file, detector: "route_confusion", type: f.type,
        signature: deriveSignature("route_confusion", f.type),
        line: f.line, severity: f.severity, evidence: f.evidence,
      });
    }
  }

  // Cross-file privilege escalation (reverse call-graph trace) — whole-root.
  try {
    for (const f of detectCrossFilePrivesc(root)) {
      hits.push({
        file: f.file, detector: "cross_file", type: f.type,
        signature: deriveSignature("cross_file", f.type),
        line: f.line, severity: f.severity, evidence: f.evidence,
      });
    }
  } catch {
    /* cross-file is best-effort */
  }

  // Group by signature (the bug families present in the install base).
  const bySignature: Record<string, number> = {};
  for (const h of hits) bySignature[h.signature] = (bySignature[h.signature] ?? 0) + 1;

  const filtered = opts.signature ? hits.filter((h) => h.signature === opts.signature) : hits;
  const filesWithFindings = new Set(filtered.map((h) => h.file));

  return {
    root,
    files_scanned: files.length,
    files_with_findings: filesWithFindings.size,
    total_findings: filtered.length,
    signature: opts.signature ?? null,
    by_signature: bySignature,
    hits: filtered.map((h) => ({
      file: h.file, detector: h.detector, type: h.type, signature: h.signature,
      line: h.line, severity: h.severity,
    })),
  };
}
