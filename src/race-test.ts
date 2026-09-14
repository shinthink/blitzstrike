/** Race Condition / TOCTOU Tester — concurrency idempotency oracle.
 *
 *  Many apps are STATEFUL yet assume a request is handled atomically. A TOCTOU
 *  race (time-of-check vs time-of-use) lets N concurrent requests each pass the
 *  "check" (balance > 0, coupon unused, one vote) before any commits the "use",
 *  producing duplicate side effects — double-spend, duplicate orders, discount
 *  abuse, mass account action.
 *
 *  Deterministic + evidence-first: fire a SANITY request (1 → should succeed),
 *  then a CONCURRENT BURST of N identical requests, and count how many succeed.
 *  If more succeed than expected_max (default 1), the operation is not atomic
 *  under concurrency → race. The success criterion is a caller-supplied regex
 *  (the "marker" of a committed side effect).
 */
import { sha256 } from "./evidence.js";

export interface RaceVerdict {
  race: boolean;
  verdict: string;
}

/** Pure classifier: did more concurrent requests succeed than expected? */
export function classifyRace(input: { successes: number; total: number; expected_max: number }): RaceVerdict {
  const race = input.successes > input.expected_max;
  return {
    race,
    verdict: race
      ? `race condition / idempotency violation — ${input.successes} of ${input.total} concurrent requests succeeded (expected ≤ ${input.expected_max}).`
      : `no race — ${input.successes} of ${input.total} succeeded (within expected ${input.expected_max}).`,
  };
}

export async function raceTest(input: {
  url: string;
  method?: string;
  body?: string;
  headers?: Record<string, string>;
  success_pattern: string;
  concurrent?: number;
  expected_max?: number;
  timeoutMs?: number;
}): Promise<Record<string, unknown>> {
  const method = input.method ?? "POST";
  const N = input.concurrent ?? 10;
  const expected = input.expected_max ?? 1;
  const successRe = new RegExp(input.success_pattern, "i");
  const timeoutMs = input.timeoutMs ?? 10000;
  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike race probe)", ...(input.headers ?? {}) };

  const doFetch = async (): Promise<{ status: number; body: string; error?: string }> => {
    try {
      const r = await fetch(input.url, { method, body: input.body, headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      return { status: r.status, body: await r.text() };
    } catch (e) {
      return { status: 0, body: "", error: String(e) };
    }
  };

  // Concurrent burst — N identical requests fired in parallel against a FRESH
  // resource (the caller must ensure the target is in its initial state; the
  // test does not pre-consume it with a sanity request).
  const results = await Promise.all(Array.from({ length: N }, () => doFetch()));
  const successes = results.filter((r) => r.status > 0 && successRe.test(r.body)).length;
  const errors = results.filter((r) => r.error).length;

  const verdict = classifyRace({ successes, total: N, expected_max: expected });

  return {
    url: input.url,
    method,
    concurrent_requests: N,
    expected_max: expected,
    concurrent_successes: successes,
    fetch_errors: errors,
    success_rate: Number((successes / N).toFixed(3)),
    race_detected: verdict.race,
    verdict: verdict.verdict,
    detail: verdict.race
      ? "multiple concurrent requests each passed the check before any committed the side effect (TOCTOU)."
      : "the operation appears atomic/idempotent under this concurrency (a tighter single-packet burst via HTTP/2 may still win; this is a parallel-request approximation).",
  };
}

/** Stable hash of a request signature (marker for dedup/diffing). */
export function requestSignature(method: string, url: string, body?: string): string {
  return sha256(`${method}\u0000${url}\u0000${body ?? ""}`).slice(0, 16);
}
