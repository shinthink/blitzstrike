/** Finding deduplication (§38 "Finding deduplication").
 *
 * Collapse multiple findings that share a ROOT CAUSE into one, regardless of
 * which file/scan produced them. The signature is the (sink type, source type,
 * cwe) triple — the minimum that identifies "the same bug class reached the
 * same way". Two findings with the same signature but different endpoints are
 * variants of one root cause, so they collapse.
 */
import type { Finding } from "./finding.js";

/** A stable, order-independent signature for a finding's root cause. */
export function rootCauseSignature(finding: Finding): string {
  const sinkType = (finding.sink?.type ?? "unknown").toLowerCase();
  const sourceType = (finding.source?.type ?? "unknown").toLowerCase();
  const cwe = (finding.classification?.cwe ?? "").toUpperCase();
  return [sinkType, sourceType, cwe].filter(Boolean).join("|");
}

export interface DedupGroup {
  signature: string;
  count: number;
  representative: Finding;
  findings: Finding[];
}

/** Group findings by root-cause signature, preserving order of first appearance. */
export function dedupFindings(findings: Finding[]): DedupGroup[] {
  const groups = new Map<string, DedupGroup>();
  for (const f of findings) {
    const sig = rootCauseSignature(f);
    const existing = groups.get(sig);
    if (existing) {
      existing.count += 1;
      existing.findings.push(f);
    } else {
      groups.set(sig, { signature: sig, count: 1, representative: f, findings: [f] });
    }
  }
  return [...groups.values()];
}

/** Reduce a list to one finding per root cause (the representative). */
export function uniqueFindings(findings: Finding[]): Finding[] {
  return dedupFindings(findings).map((g) => g.representative);
}
