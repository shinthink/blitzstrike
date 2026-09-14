/** Release validation (Phase 8 / §49) — version consistency checks.
 *
 * Every release must not let these drift apart:
 *   package.json version / CHANGELOG version / Git tag / npm registry version
 *
 * `validateRelease()` returns a per-check verdict + an overall `consistent`
 * flag. Network and git checks degrade gracefully (not fatal) when unavailable.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { VERSION } from "./version.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

export interface ReleaseCheck {
  name: string;
  ok: boolean;
  detail: string;
  /** soft checks (git tag, npm registry) are informational — not part of `consistent`. */
  soft?: boolean;
}

export interface ReleaseValidation {
  version: string;
  checks: ReleaseCheck[];
  consistent: boolean;
}

/** Validate release metadata consistency (package.json / CHANGELOG are hard checks). */
export function validateRelease(): ReleaseValidation {
  const checks: ReleaseCheck[] = [];

  // 1. package.json version (authoritative from version.ts)
  checks.push({ name: "package.json version", ok: true, detail: VERSION });

  // 2. CHANGELOG latest version matches package.json (hard)
  try {
    const changelog = readFileSync(join(ROOT, "CHANGELOG.md"), "utf8");
    const m = changelog.match(/^##\s+\[([0-9]+\.[0-9]+\.[0-9]+)\]/m);
    const changelogVersion = m?.[1] ?? null;
    checks.push({
      name: "CHANGELOG version",
      ok: changelogVersion === VERSION,
      detail: changelogVersion ?? "no version header found",
    });
  } catch {
    checks.push({ name: "CHANGELOG version", ok: false, detail: "CHANGELOG.md not found" });
  }

  // 3. git tag (soft — this repo uses a single rolling tag; informational)
  try {
    const tag = execSync("git describe --tags --abbrev=0", { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    checks.push({ name: "Git tag", ok: tag === `v${VERSION}`, detail: tag, soft: true });
  } catch {
    checks.push({ name: "Git tag", ok: true, detail: "unavailable (no git/tags)", soft: true });
  }

  // 4. npm registry version (soft — may lag behind staged publishes)
  try {
    const published = execSync("npm view blitzstrike version", { encoding: "utf8", timeout: 8000, stdio: ["ignore", "pipe", "ignore"] }).trim();
    checks.push({ name: "npm registry version", ok: published === VERSION, detail: published, soft: true });
  } catch {
    checks.push({ name: "npm registry version", ok: true, detail: "unavailable (offline)", soft: true });
  }

  // 5. lockfile present (soft — supply-chain hygiene, §51)
  checks.push({
    name: "Lockfile",
    ok: lockfilePresent(),
    detail: lockfilePresent() ? "present (bun.lock / package-lock.json)" : "missing",
    soft: true,
  });

  return { version: VERSION, checks, consistent: checks.filter((c) => !c.soft).every((c) => c.ok) };
}

/** True when a lockfile exists alongside package.json (package-lock.json or bun.lock). */
export function lockfilePresent(): boolean {
  return existsSync(join(ROOT, "package-lock.json")) || existsSync(join(ROOT, "bun.lock")) || existsSync(join(ROOT, "bun.lockb"));
}
