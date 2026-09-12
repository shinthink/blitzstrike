/** Data sync — fetch heavy datasets (payloads + nuclei templates) on-demand.
 *
 * The npm package ships CORE only (payloads/templates are rejected by npm's
 * malware scanner). This module downloads them from the GitHub repo into the
 * local data cache (~/.blitzstrike/data/) so `payload_lookup`/`template_lookup`
 * work offline afterward.
 */
import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const DATA_ROOT = process.env.BLITZSTRIKE_DATA ?? join(homedir(), ".blitzstrike", "data");
const GITHUB_REPO = "https://github.com/shinthink/blitzstrike.git";

function dirExists(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

function countFiles(dir: string): number {
  try {
    let n = 0;
    const walk = (d: string) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) walk(join(d, e.name));
        else n++;
      }
    };
    walk(dir);
    return n;
  } catch { return 0; }
}

export interface SyncResult {
  payloads: { path: string; files: number; synced: boolean };
  templates: { path: string; files: number; synced: boolean };
  data_root: string;
}

/** Fetch payloads + templates into the data cache (git sparse clone). */
export function syncData(): SyncResult {
  if (!dirExists(DATA_ROOT)) mkdirSync(DATA_ROOT, { recursive: true });

  const payloadsPath = join(DATA_ROOT, "payloads");
  const templatesPath = join(DATA_ROOT, "templates");
  const hasPayloads = dirExists(payloadsPath) && countFiles(payloadsPath) > 0;
  const hasTemplates = dirExists(templatesPath) && countFiles(templatesPath) > 0;

  // If both already present, nothing to do.
  if (hasPayloads && hasTemplates) {
    return {
      payloads: { path: payloadsPath, files: countFiles(payloadsPath), synced: false },
      templates: { path: templatesPath, files: countFiles(templatesPath), synced: false },
      data_root: DATA_ROOT,
    };
  }

  // Try to sync from the local package (dev checkout) first.
  const localPayloads = join(ROOT, "payloads");
  const localTemplates = join(ROOT, "templates");
  let payloadsSynced = false;
  let templatesSynced = false;

  if (!hasPayloads && dirExists(localPayloads)) {
    copyDir(localPayloads, payloadsPath);
    payloadsSynced = true;
  }
  if (!hasTemplates && dirExists(localTemplates)) {
    copyDir(localTemplates, templatesPath);
    templatesSynced = true;
  }

  // Fallback: sparse git clone from GitHub for whatever is still missing.
  const gitOk = spawnSync("git", ["--version"]).status === 0;
  if (gitOk && (!dirExists(payloadsPath) || countFiles(payloadsPath) === 0 || !dirExists(templatesPath) || countFiles(templatesPath) === 0)) {
    const tmp = join(DATA_ROOT, ".tmp-clone");
    if (dirExists(tmp)) rmSync(tmp, { recursive: true, force: true });
    const r = spawnSync("git", ["clone", "--depth", "1", "--filter=blob:none", "--sparse", GITHUB_REPO, tmp], { timeout: 120000 });
    if (r.status === 0) {
      const sparse = spawnSync("git", ["-C", tmp, "sparse-checkout", "set", "payloads", "templates"], { timeout: 120000 });
      if (sparse.status === 0) {
        if (!dirExists(payloadsPath) || countFiles(payloadsPath) === 0) {
          copyDir(join(tmp, "payloads"), payloadsPath);
          payloadsSynced = true;
        }
        if (!dirExists(templatesPath) || countFiles(templatesPath) === 0) {
          copyDir(join(tmp, "templates"), templatesPath);
          templatesSynced = true;
        }
      }
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  return {
    payloads: { path: payloadsPath, files: countFiles(payloadsPath), synced: payloadsSynced },
    templates: { path: templatesPath, files: countFiles(templatesPath), synced: templatesSynced },
    data_root: DATA_ROOT,
  };
}

function copyDir(src: string, dst: string): void {
  // use cp -r for robustness
  const r = spawnSync("cp", ["-r", src, dst], { timeout: 120000 });
  if (r.status !== 0) {
    // fallback: manual recursive copy
    manualCopy(src, dst);
  }
}

function manualCopy(src: string, dst: string): void {
  mkdirSync(dst, { recursive: true });
  for (const e of readdirSync(src, { withFileTypes: true })) {
    const s = join(src, e.name);
    const d = join(dst, e.name);
    if (e.isDirectory()) manualCopy(s, d);
    else writeFileSync(d, readFileSync(s));
  }
}
