/** Evidence grounding — the deterministic anti-hallucination check.
 *
 * A finding's "evidence" is only real if it is a byte-exact (or closely-derived)
 * substring of the ACTUAL tool output it claims to quote. This module turns the
 * `evidence_grounding` doctrine into a MECHANICAL check: instead of trusting the
 * model's paraphrase, we locate the quoted string inside the real receipt.
 *
 * Fallback chain (strict -> lenient), matching the strongest known pattern in
 * agentic security tooling:
 *   1. exact        — verbatim contiguous substring
 *   2. normalized   — exact after CRLF/LF/unicode-whitespace normalization
 *   3. line-span    — the evidence's non-empty lines appear IN ORDER in the output
 *   4. line-envelope — the evidence's lines appear, but not necessarily in order
 *   5. cross-receipt — lines may span multiple receipts (projected in sequence)
 *
 * Verdicts:
 *   grounded    — matched by exact/normalized/line-span (quote is real, traceable)
 *   envelope    — only line-envelope matched (weak: lines present but scattered)
 *   ungrounded  — no match anywhere: the quote cannot be located -> REJECT
 *   inconclusive — output was truncated and nothing matched: cannot conclude
 *                  (a truncated receipt can NEVER complete a finding, but it also
 *                   must not be treated as a disproof)
 */

export type GroundingMethod = "exact" | "normalized" | "line-span" | "line-envelope" | "cross-receipt";

export type GroundingVerdict = "grounded" | "envelope" | "ungrounded" | "inconclusive";

export interface GroundingResult {
  grounded: boolean;
  verdict: GroundingVerdict;
  method: GroundingMethod | null;
  /** Character span of the match in the matched receipt (exact/normalized only). */
  span?: { receiptIndex: number; start: number; end: number };
  matchedLines?: number;
  totalLines?: number;
  detail: string;
}

const FALLBACK_RECEIPT_CHARS = 4000;

function normalizeWhitespace(s: string): string {
  return s.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/[^\S\n]+/g, " ").trim();
}

function nonEmptyLines(s: string): string[] {
  return s
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/** Locate a contiguous substring; returns char offset or -1. */
function indexOfExact(haystack: string, needle: string): number {
  return haystack.indexOf(needle);
}

/** Locate a normalized substring in a normalized haystack. */
function indexOfNormalized(haystack: string, needle: string): number {
  return normalizeWhitespace(haystack).indexOf(normalizeWhitespace(needle));
}

/** Ordered line-span match: every evidence line appears in order (increasing offset). */
function lineSpanMatch(output: string, lines: string[]): { matched: number; total: number; span?: { start: number; end: number } } {
  let cursor = 0;
  let first = -1;
  let last = -1;
  for (const line of lines) {
    const idx = output.indexOf(line, cursor);
    if (idx === -1) return { matched: lines.indexOf(line), total: lines.length };
    if (first === -1) first = idx;
    last = idx + line.length;
    cursor = idx + line.length;
  }
  return { matched: lines.length, total: lines.length, span: { start: first, end: last } };
}

/** Line-envelope match: every evidence line appears somewhere (any order). */
function lineEnvelopeMatch(output: string, lines: string[]): { matched: number; total: number } {
  let matched = 0;
  for (const line of lines) {
    if (output.includes(line)) matched++;
  }
  return { matched, total: lines.length };
}

function attempt(receiptIndex: number, output: string, evidence: string, lines: string[]): { method: GroundingMethod; span?: { receiptIndex: number; start: number; end: number }; matchedLines: number; totalLines: number } | null {
  const exact = indexOfExact(output, evidence);
  if (exact !== -1) {
    return { method: "exact", span: { receiptIndex, start: exact, end: exact + evidence.length }, matchedLines: lines.length, totalLines: lines.length };
  }
  if (normalizeWhitespace(evidence).length > 0) {
    const norm = indexOfNormalized(output, evidence);
    if (norm !== -1) {
      return { method: "normalized", span: { receiptIndex, start: norm, end: norm + normalizeWhitespace(evidence).length }, matchedLines: lines.length, totalLines: lines.length };
    }
  }
  const span = lineSpanMatch(output, lines);
  if (span.matched === lines.length) {
    return { method: "line-span", span: span.span ? { receiptIndex, start: span.span.start, end: span.span.end } : undefined, matchedLines: span.matched, totalLines: span.total };
  }
  const env = lineEnvelopeMatch(output, lines);
  if (env.matched === lines.length) {
    return { method: "line-envelope", matchedLines: env.matched, totalLines: env.total };
  }
  return null;
}

/** Verify that a claimed evidence string is grounded in the actual tool output.
 *  @param evidence the claimed quote (what the model says it observed)
 *  @param outputs  the actual tool output(s) — one string or an array (multi-receipt)
 *  @param opts.truncated mark the output as truncated (then "not found" is inconclusive, not a rejection) */
export function verifyEvidenceGrounding(
  evidence: string,
  outputs: string | string[],
  opts?: { truncated?: boolean },
): GroundingResult {
  const receipts = Array.isArray(outputs) ? outputs : [outputs];
  const ev = (evidence ?? "").toString().trim();
  const lines = nonEmptyLines(ev);

  if (ev.length === 0 || lines.length === 0) {
    return { grounded: false, verdict: "ungrounded", method: null, detail: "empty evidence string — nothing to ground" };
  }

  // Strongest first: per-receipt exact / normalized / line-span / envelope.
  let envelopeHit: { method: "line-envelope"; matchedLines: number; totalLines: number } | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = attempt(i, receipts[i], ev, lines);
    if (!r) continue;
    if (r.method === "line-envelope") {
      envelopeHit = { method: "line-envelope", matchedLines: r.matchedLines, totalLines: r.totalLines };
      continue;
    }
    return {
      grounded: true,
      verdict: "grounded",
      method: r.method,
      span: r.span,
      matchedLines: r.matchedLines,
      totalLines: r.totalLines,
      detail: `evidence located via ${r.method} in receipt #${i}`,
    };
  }

  // Cross-receipt: the evidence lines are spread across receipts in sequence.
  if (receipts.length > 1) {
    const joined = receipts.join("\n");
    const span = lineSpanMatch(joined, lines);
    if (span.matched === lines.length) {
      return { grounded: true, verdict: "grounded", method: "cross-receipt", matchedLines: span.matched, totalLines: span.total, detail: "evidence lines span multiple receipts, in order" };
    }
    const env = lineEnvelopeMatch(joined, lines);
    if (env.matched === lines.length) {
      envelopeHit = { method: "line-envelope", matchedLines: env.matched, totalLines: env.total };
    }
  }

  // Bounded fallback: re-check against the tail of the last receipt.
  const lastReceipt = receipts[receipts.length - 1] ?? "";
  if (lastReceipt.length > FALLBACK_RECEIPT_CHARS) {
    const tail = lastReceipt.slice(-FALLBACK_RECEIPT_CHARS);
    const r = attempt(receipts.length - 1, tail, ev, lines);
    if (r && r.method !== "line-envelope") {
      return { grounded: true, verdict: "grounded", method: r.method, span: r.span, matchedLines: r.matchedLines, totalLines: r.totalLines, detail: `evidence located in the tail of the last receipt (${FALLBACK_RECEIPT_CHARS}-char window)` };
    }
  }

  if (envelopeHit) {
    return {
      grounded: false,
      verdict: "envelope",
      method: "line-envelope",
      matchedLines: envelopeHit.matchedLines,
      totalLines: envelopeHit.totalLines,
      detail: "evidence lines are present but NOT in a traceable contiguous order — treat as weak, prefer a verbatim quote",
    };
  }

  if (opts?.truncated) {
    return { grounded: false, verdict: "inconclusive", method: null, matchedLines: 0, totalLines: lines.length, detail: "output was truncated and the evidence was not located — a truncated receipt can neither confirm nor refute" };
  }

  return { grounded: false, verdict: "ungrounded", method: null, matchedLines: 0, totalLines: lines.length, detail: "evidence could not be located in any receipt — the quote is not grounded in real tool output; reject or downgrade the finding" };
}
