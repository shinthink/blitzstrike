/** Surface-first targeting — map an attack surface to its highest-value tests.
 *
 *  Derived from public target-recon dossiers: a large target is won by mapping
 *  each of its attack SURFACES (image proxy, redirect proxy, edge cache,
 *  payment portal, AI agent, file service, Electron app, SSO portal) to the
 *  small set of high-value test cases for that surface — not by spraying
 *  payloads across every endpoint. `matchSurfaces` fingerprints the detected
 *  stack (techs + headers + body) against the surface map; `surfaceMap`
 *  returns the map for a keyword hint.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

export interface SurfaceEntry {
  id: string;
  name: string;
  fingerprints: string[];
  high_value_tests: string[];
}

interface SurfaceMapData {
  surfaces: SurfaceEntry[];
  note: string;
}

function load(): SurfaceMapData {
  const raw = readFileSync(join(ROOT, "intelligence", "surface-map.json"), "utf8");
  return JSON.parse(raw) as SurfaceMapData;
}

/** Return the full surface map (for enumeration / listing). */
export function surfaceMap(hint = ""): SurfaceEntry[] {
  const data = load();
  if (!hint) return data.surfaces;
  const h = hint.toLowerCase();
  return data.surfaces.filter(
    (s) => s.id.includes(h) || s.name.toLowerCase().includes(h) || s.fingerprints.some((f) => f.toLowerCase().includes(h)),
  );
}

/** Fingerprint the detected stack against the surface map — returns the surfaces
 *  present (each with its high-value tests), ordered by fingerprint hit count. */
export function matchSurfaces(techs: string[], headers: Record<string, string> = {}, body = ""): Array<SurfaceEntry & { hits: string[] }> {
  const haystack = `${techs.join(" ")} ${Object.keys(headers).join(" ")} ${Object.values(headers).join(" ")} ${body}`.toLowerCase();
  const out: Array<SurfaceEntry & { hits: string[] }> = [];
  for (const s of load().surfaces) {
    const hits = s.fingerprints.filter((f) => haystack.includes(f.toLowerCase()));
    if (hits.length > 0) out.push({ ...s, hits });
  }
  return out.sort((a, b) => b.hits.length - a.hits.length);
}
