/** Caching layer (Phase 8 / §46) — versioned, in-memory result cache.
 *
 * Caches parse/AST/call-graph/flow results so repeated analysis of unchanged
 * source does not re-parse. Cache keys MUST include relevant versions so stale
 * entries are never served after an engine change:
 *
 *   key = sha256(source) + engine_version + kind
 *
 * Accuracy is never sacrificed for speed — the cache is keyed on exact source
 * content hash + engine version, so any source or engine change invalidates it.
 */
import { createHash } from "node:crypto";
import { VERSION } from "./version.js";

const mem = new Map<string, unknown>();
let hits = 0;
let misses = 0;

/** Build a versioned cache key for a (kind, source) pair. */
export function cacheKey(kind: string, source: string): string {
  const h = createHash("sha256").update(source).digest("hex").slice(0, 20);
  return `${kind}:${VERSION}:${h}`;
}

/** Retrieve a cached value, or undefined on miss. */
export function getCache<T>(kind: string, source: string): T | undefined {
  const k = cacheKey(kind, source);
  if (mem.has(k)) {
    hits += 1;
    return mem.get(k) as T;
  }
  misses += 1;
  return undefined;
}

/** Store a value in the cache. */
export function setCache<T>(kind: string, source: string, value: T): T {
  mem.set(cacheKey(kind, source), value);
  return value;
}

/** Run a function with caching: reuse a cached result for the same (kind, source). */
export function withCache<T>(kind: string, source: string, compute: () => T): T {
  const hit = getCache<T>(kind, source);
  if (hit !== undefined) return hit;
  return setCache(kind, source, compute());
}

export interface CacheStats {
  size: number;
  hits: number;
  misses: number;
  hit_ratio: number;
}

export function cacheStats(): CacheStats {
  return {
    size: mem.size,
    hits,
    misses,
    hit_ratio: hits + misses === 0 ? 0 : Number((hits / (hits + misses)).toFixed(3)),
  };
}

export function clearCache(): void {
  mem.clear();
  hits = 0;
  misses = 0;
}
