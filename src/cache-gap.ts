/** Cache Key Normalization Gap Fuzzer — live web-cache deception/poisoning
 *  detection (black-box, no source code).
 *
 *  CDNs and reverse proxies often disagree with the origin about how a URL path
 *  is normalized. The cache keys on one form (`/account/style.css` → cached as
 *  a static asset) while the origin resolves a different resource (the `/account`
 *  page with private data). That gap is web-cache deception / poisoning — a
 *  high-impact bug class that is still under-hunted.
 *
 *  Deterministic + evidence-first: fetch a baseline, then probe every
 *  normalization/extension variant, compare the body hash + cache headers, and
 *  flag only the cases where sensitive content is served under a cacheable path.
 */
import { sha256 } from "./evidence.js";

/** Generate the path-normalization + static-extension variants for an endpoint. */
export function generateCacheVariants(endpoint: string): string[] {
  const e = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
  const variants = new Set<string>();
  const add = (s: string) => variants.add(s);

  // Static extensions the origin may ignore (serving the endpoint's content
  // under a path a cache treats as a static, cacheable asset).
  const exts = [".css", ".js", ".png", ".jpg", ".jpeg", ".json", ".txt", ".ico", ".html", ".svg", ".woff", ".xml", ".gif"];
  for (const ext of exts) {
    add(`${e}${ext}`);
    add(`${e}/${ext.slice(1)}`);
    add(`${e}${ext}?x=1`);
    add(`${e}${ext};`);
    add(`${e}${ext}%3b`);
  }

  // Path-normalization gaps (dot-segments, encoded slashes, semicolons, nulls).
  const suffix = [
    "/style.css", "/..;/style.css", "/.;/style.css", "/../style.css",
    "/%2e%2e/style.css", "/%2fstyle.css", "/;style.css", "/%3bstyle.css",
    "/./style.css", "//style.css", "/%00.style.css", "/style.css/.",
    "/style.css%2f", "/style.css%00", "/style.css%2e%2e",
  ];
  for (const s of suffix) add(`${e}${s}`);

  // Encoded / alternate forms of the endpoint itself.
  add(e.replace(/^\//, "/%2f"));
  add(e.replace(/^\//, "//"));
  add(e.replace(/^\//, "/./"));
  add(e.replace(/^\//, "/%2e/"));
  add(e.replace(/^\//, "/..;/"));
  add(`${e}%00`);
  add(`${e};`);
  add(`${e}%3b`);
  add(`${e}?`);
  add(`${e}?x=1`);
  add(`${e}#`);
  add(e.toUpperCase());

  return [...variants].filter((v) => v !== e);
}

export interface CacheVariantVerdict {
  same_body: boolean;
  cacheable: boolean;
  cache_status: string | null;
  gap: "cache_deception" | "normalization_gap" | null;
  detail: string;
}

/** Classify one variant response against the baseline (pure, deterministic). */
export function classifyCacheResponse(input: {
  baselineHash: string;
  bodyHash: string;
  status: number;
  headers: Record<string, string>;
  staticExtension: boolean;
}): CacheVariantVerdict {
  const same = input.bodyHash === input.baselineHash;
  const lower = Object.fromEntries(Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const cacheStatus = lower["x-cache"] ?? lower["cf-cache-status"] ?? lower["x-served-by"] ?? lower["x-cache-status"] ?? null;
  const cacheControl = lower["cache-control"] ?? "";
  const age = lower["age"];
  const cacheable =
    /public|max-age|s-maxage/.test(cacheControl) ||
    age !== undefined ||
    (cacheStatus !== null && /hit/i.test(cacheStatus)) ||
    input.staticExtension;

  if (same && input.staticExtension && cacheable) {
    return {
      same_body: true, cacheable, cache_status: cacheStatus, gap: "cache_deception",
      detail: "the endpoint's content is returned for a static-extension path that is cacheable — a cache may store PRIVATE content under a PUBLIC static key (cache deception).",
    };
  }
  if (same && cacheStatus !== null && /hit/i.test(cacheStatus)) {
    return {
      same_body: true, cacheable, cache_status: cacheStatus, gap: "cache_deception",
      detail: `the endpoint's content is served from cache (${cacheStatus}) — the response is being cached and shared.`,
    };
  }
  if (!same && input.staticExtension && input.status !== 200) {
    return {
      same_body: false, cacheable, cache_status: cacheStatus, gap: "normalization_gap",
      detail: "the static-extension variant resolves differently than the baseline (origin normalized the path) — cache key may diverge from the origin resource (normalization gap).",
    };
  }
  return { same_body: same, cacheable, cache_status: cacheStatus, gap: null, detail: "" };
}

function headersToRecord(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

function pickCacheHeaders(h: Record<string, string>): Record<string, string> {
  const keys = ["cache-control", "age", "expires", "x-cache", "cf-cache-status", "x-served-by", "x-cache-status", "via", "etag", "last-modified", "vary"];
  const out: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) out[k] = h[k];
  return out;
}

export async function cacheGapScan(baseUrl: string, endpoint: string, opts: { maxVariants?: number; timeoutMs?: number } = {}): Promise<Record<string, unknown>> {
  const base = baseUrl.replace(/\/+$/, "");
  const endpointPath = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
  const variants = generateCacheVariants(endpointPath).slice(0, opts.maxVariants ?? 60);

  const headers = { "User-Agent": "Mozilla/5.0 (blitzstrike cache probe)", Accept: "*/*" };

  let baselineHash = "";
  let baselineStatus = 0;
  let baselineHeaders: Record<string, string> = {};
  try {
    const resp = await fetch(base + endpointPath, { headers, redirect: "manual", signal: AbortSignal.timeout(opts.timeoutMs ?? 8000) });
    baselineStatus = resp.status;
    baselineHeaders = headersToRecord(resp.headers);
    baselineHash = sha256(await resp.text());
  } catch (e) {
    return { error: "baseline fetch failed", base_url: base, endpoint: endpointPath, detail: String(e) };
  }

  const results: Array<Record<string, unknown>> = [];
  for (const v of variants) {
    try {
      const resp = await fetch(base + v, { headers, redirect: "manual", signal: AbortSignal.timeout(opts.timeoutMs ?? 8000) });
      const status = resp.status;
      const hdrs = headersToRecord(resp.headers);
      const bodyHash = sha256(await resp.text());
      const staticExtension = /\.(css|js|png|jpe?g|json|txt|ico|html|svg|woff|xml|gif)([;?].*)?$/i.test(v);
      const cls = classifyCacheResponse({ baselineHash, bodyHash, status, headers: hdrs, staticExtension });
      results.push({ path: v, status, same_body: cls.same_body, cacheable: cls.cacheable, cache_status: cls.cache_status, gap: cls.gap, detail: cls.detail });
    } catch {
      results.push({ path: v, status: 0, same_body: false, cacheable: false, cache_status: null, gap: null, detail: "fetch error/timeout" });
    }
  }

  const gaps = results.filter((r) => r.gap !== null);

  return {
    base_url: base,
    endpoint: endpointPath,
    baseline: { status: baselineStatus, body_hash: baselineHash.slice(0, 16), cache_headers: pickCacheHeaders(baselineHeaders) },
    variants_tested: results.length,
    gaps_found: gaps.length,
    gaps,
    all: results,
  };
}
