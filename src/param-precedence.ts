/** Duplicate Parameter Precedence Fuzzer — WAF/app/backend disagreement oracle.
 *
 *  When a request carries the same parameter twice (or uses an alternate
 *  delimiter), the WAF, the app, and the backend often disagree about WHICH
 *  value wins (first / last / joined). That disagreement is a WAF-bypass and
 *  authorization-bypass vector:
 *
 *      ?id=1&id=' OR 1=1--    →  WAF validates id=1, app binds id=' OR 1=1--
 *
 *  Deterministic + evidence-first: fetch baseline A and B, then probe every
 *  duplicate/delimiter variant, and classify the app's precedence + which
 *  delimiters it treats as parameter separators. Pure helpers are testable.
 */
import { sha256 } from "./evidence.js";

export interface PrecedenceVariant {
  name: string;
  /** The raw query string (excluding the leading '?'). */
  qs: string;
}

/** Generate duplicate-parameter + alternate-delimiter variants. */
export function generatePrecedenceVariants(param: string, a: string, b: string): PrecedenceVariant[] {
  const enc = encodeURIComponent;
  const variants: PrecedenceVariant[] = [
    { name: "duplicate_amp", qs: `${enc(param)}=${enc(a)}&${enc(param)}=${enc(b)}` },
    { name: "semicolon", qs: `${enc(param)}=${enc(a)};${enc(param)}=${enc(b)}` },
    { name: "comma", qs: `${enc(param)}=${enc(a)},${enc(param)}=${enc(b)}` },
    { name: "encoded_amp", qs: `${enc(param)}=${enc(a)}%26${enc(param)}=${enc(b)}` },
    { name: "encoded_semicolon", qs: `${enc(param)}=${enc(a)}%3b${enc(param)}=${enc(b)}` },
    { name: "pipe", qs: `${enc(param)}=${enc(a)}|${enc(param)}=${enc(b)}` },
    { name: "array", qs: `${enc(param)}[]=${enc(a)}&${enc(param)}[]=${enc(b)}` },
    { name: "null_byte", qs: `${enc(param)}=${enc(a)}%00${enc(b)}` },
    { name: "space", qs: `${enc(param)}=${enc(a)}+${enc(b)}` },
  ];
  return variants;
}

export interface PrecedenceResult {
  name: string;
  qs: string;
  status: number;
  body_hash: string;
  winner: "A" | "B" | "neither" | "joined";
  split: boolean;
  detail: string;
}

/** Pure classifier: which baseline (A/B) a variant response matches. */
export function classifyPrecedence(input: {
  hashA: string;
  hashB: string;
  bodyHash: string;
  name: string;
}): { winner: "A" | "B" | "neither" | "joined"; split: boolean; detail: string } {
  const h = input.bodyHash;
  if (h === input.hashA) {
    return { winner: "A", split: true, detail: "value A won (the first/leftmost value) — first-wins precedence for this delimiter." };
  }
  if (h === input.hashB) {
    return { winner: "B", split: true, detail: "value B won (the last/rightmost value) — last-wins precedence for this delimiter." };
  }
  // Neither matched exactly: the app may have joined the values (or treated
  // the delimiter literally as one value).
  return { winner: "neither", split: false, detail: "neither A nor B matched — the delimiter may be literal (not a parameter separator) or the values were joined." };
}

export async function paramPrecedenceScan(baseUrl: string, param: string, valueA: string, valueB: string, opts: { timeoutMs?: number } = {}): Promise<Record<string, unknown>> {
  const base = baseUrl.replace(/\/+$/, "");
  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike precedence probe)" };
  const timeoutMs = opts.timeoutMs ?? 8000;
  const enc = encodeURIComponent;

  const fetchHash = async (qs: string): Promise<{ status: number; hash: string; error?: string }> => {
    try {
      const r = await fetch(`${base}?${qs}`, { headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      const body = await r.text();
      return { status: r.status, hash: sha256(body) };
    } catch (e) {
      return { status: 0, hash: "", error: String(e) };
    }
  };

  const baseA = await fetchHash(`${enc(param)}=${enc(valueA)}`);
  const baseB = await fetchHash(`${enc(param)}=${enc(valueB)}`);

  if (baseA.error || baseB.error) {
    return { error: "baseline fetch failed", base_url: base, param, detail: baseA.error ?? baseB.error };
  }
  // A and B must differ for a meaningful oracle.
  if (baseA.hash === baseB.hash) {
    return { error: "baseline A and B produce identical responses — pick two values with a distinguishable effect", base_url: base, param };
  }

  const variants = generatePrecedenceVariants(param, valueA, valueB);
  const results: Array<Record<string, unknown>> = [];
  let firstWins = 0;
  let lastWins = 0;

  for (const v of variants) {
    const r = await fetchHash(v.qs);
    if (r.error) {
      results.push({ name: v.name, qs: v.qs, status: 0, body_hash: "", winner: "neither", split: false, detail: "fetch error/timeout" });
      continue;
    }
    const cls = classifyPrecedence({ hashA: baseA.hash, hashB: baseB.hash, bodyHash: r.hash, name: v.name });
    if (cls.winner === "A") firstWins++;
    else if (cls.winner === "B") lastWins++;
    results.push({ name: v.name, qs: v.qs, status: r.status, body_hash: r.hash.slice(0, 12), winner: cls.winner, split: cls.split, detail: cls.detail });
  }

  let precedence = "ambiguous";
  if (firstWins > 0 && lastWins === 0) precedence = "first_wins";
  else if (lastWins > 0 && firstWins === 0) precedence = "last_wins";
  else if (firstWins > 0 && lastWins > 0) precedence = "mixed_by_delimiter";

  return {
    base_url: base,
    param,
    value_a: valueA,
    value_b: valueB,
    precedence,
    first_wins_count: firstWins,
    last_wins_count: lastWins,
    variants_tested: results.length,
    results,
    waf_bypass_hint:
      precedence === "first_wins"
        ? "the app uses the FIRST duplicate value — a WAF that inspects the LAST value is bypassed with ?param=benign&param=payload."
        : precedence === "last_wins"
          ? "the app uses the LAST duplicate value — a WAF that inspects the FIRST value is bypassed with ?param=payload&param=benign."
          : "precedence is mixed by delimiter — map which delimiter the WAF validates vs which the app binds, then inject via the disagreement.",
  };
}
