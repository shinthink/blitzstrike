/** Dependency security (Phase 8 / §50) — supply-chain surface checks.
 *
 * Inspects the package's own install-time scripts and git/unusual dependency
 * sources. Prefer minimal dependencies; never execute arbitrary code at install
 * time. This is a fast, deterministic static check (no network required).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

interface PackageJson {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface DependencyReport {
  install_scripts: Array<{ name: string; command: string }>;
  git_dependencies: string[];
  total_dependencies: number;
  safe: boolean;
}

/** Inspect the package's own dependency surface (no network). */
export function checkDependencies(): DependencyReport {
  let pkg: PackageJson = {};
  try {
    pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as PackageJson;
  } catch {
    return { install_scripts: [], git_dependencies: [], total_dependencies: 0, safe: false };
  }

  // Install-time scripts (run on `npm install` of this package — must be absent).
  const installScriptNames = ["preinstall", "install", "postinstall", "prepare"];
  const installScripts = installScriptNames
    .filter((n) => pkg.scripts?.[n])
    .map((n) => ({ name: n, command: pkg.scripts![n] }));

  // Git / unusual dependency sources.
  const allDeps = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
    ...(pkg.peerDependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
  };
  const gitDependencies = Object.entries(allDeps)
    .filter(([, v]) => /^(git\+|git:|github:|gitlab:|bitbucket:|\w+:\/\/)/.test(v))
    .map(([name, v]) => `${name}@${v}`);

  const total = Object.keys(allDeps).length;
  return {
    install_scripts: installScripts,
    git_dependencies: gitDependencies,
    total_dependencies: total,
    safe: installScripts.length === 0 && gitDependencies.length === 0,
  };
}
