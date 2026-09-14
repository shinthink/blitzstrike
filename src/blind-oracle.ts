/** Blind Differential Oracle — calibration-based blind-vuln detection.
 *
 *  Detects which sink a request parameter reaches WITHOUT sending a malicious
 *  payload. The technique is CALIBRATION + DIFFERENTIAL: send a baseline, then
 *  benign ARITHMETIC / encoding variants, and infer the sink from the byte-level
 *  response difference.
 *
 *    SQL/expression : `id=1` vs `id=1+0` / `id=2-1` — if the same record comes
 *                     back, the param is evaluated arithmetically (SQL context).
 *    SSTI           : `name=test` vs `name=test${7*7}` — if "49" renders, the
 *                     param reaches a template engine.
 *    XSS reflection : a unique marker `<zzMARK>` — if it reflects RAW, the param
 *                     reaches unescaped HTML output.
 *
 *  All probes are benign (numbers + operators, no quotes/commands), so they do
 *  not trigger WAF — yet the differential is a deterministic, evidence-backed
 *  signal. Pure helpers (probe generation + inference) are unit-testable.
 */
import { sha256 } from "./evidence.js";

export interface Probe {
  sink: string;
  name: string;
  payload: string;
}

/** Benign arithmetic/coercion probes (only for numeric baselines). */
export function arithmeticProbes(value: string): Probe[] {
  const n = Number(value);
  if (Number.isNaN(n) || value.trim() === "") return [];
  return [
    { sink: "sql_arithmetic", name: "plus_zero", payload: `${n}+0` },
    { sink: "sql_arithmetic", name: "minus_zero", payload: `${n}-0` },
    { sink: "sql_arithmetic", name: "times_one", payload: `${n}*1` },
    { sink: "sql_coercion", name: "leading_zero", payload: `0${value}` },
    { sink: "sql_coercion", name: "float_form", payload: `${n}.0` },
  ];
}

/** Benign SSTI arithmetic probes (the engine renders 7*7 = 49 if templated). */
export function sstiProbes(value: string): Probe[] {
  return [
    { sink: "ssti", name: "dollar_math", payload: `${value}\${7*7}` },
    { sink: "ssti", name: "hash_math", payload: `${value}#{7*7}` },
    { sink: "ssti", name: "mustache_math", payload: `${value}{{7*7}}` },
  ];
}

/** Benign XSS reflection probe (a unique marker, no angle-bracket payload). */
export function xssProbe(value: string, marker: string): Probe {
  return { sink: "xss", name: "marker", payload: `${value}${marker}` };
}

export interface BlindProbeResult {
  sink: string;
  name: string;
  payload: string;
  status: number;
  size: number;
  timing_ms: number;
  body_hash: string;
  same_as_baseline: boolean;
  signal: boolean;
  reason: string;
}

/** Pure inference: classify each probe result against the baseline. */
export function classifyBlindProbe(input: {
  baselineHash: string;
  baselineSize: number;
  bodyHash: string;
  size: number;
  sink: string;
  name: string;
  body: string;
  marker?: string;
}): { same_as_baseline: boolean; signal: boolean; reason: string } {
  const same = input.bodyHash === input.baselineHash;
  let signal = false;
  let reason = "";

  if (input.sink === "sql_arithmetic" && same) {
    signal = true;
    reason = "arithmetic identity returned the SAME result as the bare value — the parameter is evaluated arithmetically (SQL/expression context).";
  } else if (input.sink === "sql_coercion" && same) {
    signal = true;
    reason = "type-coerced variant returned the SAME result — the parameter is normalized numerically (SQL typed column).";
  } else if (input.sink === "ssti" && !same && /49/.test(input.body)) {
    // The arithmetic 7*7 rendered as 49 in a body that DIFFERS from the baseline.
    signal = true;
    reason = "the SSTI arithmetic (7*7) rendered as 49 in the response — the parameter reaches a template engine (SSTI).";
  } else if (input.sink === "xss" && input.marker && input.body.includes(input.marker)) {
    signal = true;
    reason = "the unique marker was reflected in the response — the parameter reaches HTML output (reflected).";
  }
  return { same_as_baseline: same, signal, reason };
}

export async function blindOracle(baseUrl: string, param: string, value: string, opts: { sinks?: string[]; timeoutMs?: number } = {}): Promise<Record<string, unknown>> {
  const base = baseUrl.replace(/\/+$/, "");
  const sinks = opts.sinks ?? ["sql", "ssti", "xss"];
  const marker = `zz${Math.random().toString(36).slice(2, 10)}zz`;
  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike oracle probe)" };
  const timeoutMs = opts.timeoutMs ?? 8000;

  const build = (payload: string) => `${base}?${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;

  let baselineHash = "";
  let baselineSize = 0;
  let baselineStatus = 0;
  try {
    const r = await fetch(build(value), { headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
    baselineStatus = r.status;
    const body = await r.text();
    baselineHash = sha256(body);
    baselineSize = body.length;
  } catch (e) {
    return { error: "baseline fetch failed", base_url: base, param, detail: String(e) };
  }

  const probes: Probe[] = [];
  if (sinks.includes("sql")) probes.push(...arithmeticProbes(value));
  if (sinks.includes("ssti")) probes.push(...sstiProbes(value));
  if (sinks.includes("xss")) probes.push(xssProbe(value, marker));

  const results: Array<Record<string, unknown>> = [];
  for (const p of probes) {
    const t0 = Date.now();
    try {
      const r = await fetch(build(p.payload), { headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      const timing = Date.now() - t0;
      const status = r.status;
      const body = await r.text();
      const bodyHash = sha256(body);
      const cls = classifyBlindProbe({
        baselineHash, baselineSize, bodyHash, size: body.length,
        sink: p.sink, name: p.name, body, marker,
      });
      results.push({
        sink: p.sink, name: p.name, payload: p.payload, status,
        size: body.length, timing_ms: timing, body_hash: bodyHash.slice(0, 12),
        same_as_baseline: cls.same_as_baseline, signal: cls.signal, reason: cls.reason,
      });
    } catch {
      results.push({ sink: p.sink, name: p.name, payload: p.payload, status: 0, size: 0, timing_ms: 0, body_hash: "", same_as_baseline: false, signal: false, reason: "fetch error/timeout" });
    }
  }

  const signals = results.filter((r) => r.signal === true);

  return {
    base_url: base,
    param,
    value,
    baseline: { status: baselineStatus, size: baselineSize, body_hash: baselineHash.slice(0, 16) },
    probes_tested: results.length,
    signals_found: signals.length,
    signals,
    all: results,
    interpretation: "A signal means the parameter reaches that sink (evidence: the differential). Verify live before reporting — the oracle is a detection hint, not proof.",
  };
}
