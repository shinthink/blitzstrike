/** Self-update + data refresh.
 *
 * Two update surfaces exist:
 *   1. Package (code + bundled data) — refreshed via `npm i -g` / `bun add -g`
 *      (or implicitly always-latest under `npx blitzstrike`).
 *   2. Heavy data (payloads + nuclei templates) — refreshed via `syncData()`.
 *
 * `checkLatestVersion()` queries the npm registry; `runUpdate()` reports the
 * gap and refreshes the data cache in one shot.
 */
import { syncData } from "./sync.js";

/** Query the npm registry for the latest published blitzstrike version. */
export async function checkLatestVersion(timeoutMs = 10000): Promise<string | null> {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch("https://registry.npmjs.org/blitzstrike/latest", { signal: controller.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    const data = (await res.json()) as { version?: string };
    return data.version ?? null;
  } catch {
    return null;
  }
}

/** Compare two semver strings: -1 if a<b, 0 if equal, 1 if a>b. */
function semverCompare(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export interface UpdateResult {
  current: string;
  latest: string | null;
  outdated: boolean;
  update_command: string;
  data_sync: ReturnType<typeof syncData>;
}

/** Compare local version to npm latest and refresh the data cache. */
export async function runUpdate(currentVersion: string): Promise<UpdateResult> {
  const latest = await checkLatestVersion();
  const outdated = latest !== null && semverCompare(currentVersion, latest) < 0;
  return {
    current: currentVersion,
    latest,
    outdated,
    update_command: "npm install -g blitzstrike@latest   # or: bun add -g blitzstrike@latest",
    data_sync: syncData(),
  };
}
