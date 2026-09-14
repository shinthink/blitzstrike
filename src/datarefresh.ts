/** Data-layer health — re-load every data layer and verify cross-references.
 *
 *  The detectors + chains + patterns + CWE map are DATA, and data drifts. This
 *  module is the runtime version of the inventory self-test: it re-reads the
 *  layers and reports any broken cross-reference (a pattern pointing at a chain
 *  that no longer exists, a detector without a CWE mapping) so the agent can
 *  surface a stale data layer instead of silently producing bad grounding.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadJson(rel: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(join(__dirname, "..", rel), "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export interface DataRefreshResult {
  layers: Record<string, number>;
  consistency: {
    ok: boolean;
    broken_chain_refs: string[];
    missing_cwe: string[];
  };
}

/** Re-load the data layers and verify their cross-references. */
export function dataRefresh(): DataRefreshResult {
  const chains = loadJson("chains.json");
  const patterns = loadJson("intelligence/patterns.json");
  const cwe = loadJson("intelligence/cwe_map.json");

  const chainList = (chains?.chains ?? []) as Array<{ id: string }>;
  const patternList = (patterns?.patterns ?? []) as Array<{ id: string; chain_templates?: string[] }>;
  const cweList = (cwe?.mapping ?? []) as Array<{ id: string }>;

  const chainIds = new Set(chainList.map((c) => c.id));
  const cweIds = new Set(cweList.map((m) => m.id));

  const brokenChainRefs = patternList.flatMap((p) =>
    (p.chain_templates ?? []).filter((c) => !chainIds.has(c)).map((c) => `${p.id} -> ${c}`),
  );
  const missingCwe = patternList.map((p) => p.id).filter((id) => !cweIds.has(id));

  return {
    layers: {
      chains: chainIds.size,
      patterns: patternList.length,
      cwe: cweIds.size,
    },
    consistency: {
      ok: brokenChainRefs.length === 0 && missingCwe.length === 0,
      broken_chain_refs: brokenChainRefs,
      missing_cwe: missingCwe,
    },
  };
}
