/** CLI doctor + install helpers — shared by src/index.ts.
 *
 * doctor: verify runtime + catalog tools + credentials, with severity + fix.
 * install: auto-detect every installed agent CLI and write the correct MCP
 *          config to each one (Claude, Cursor, OpenCode, Codex, Hermes,
 *          Gemini, Windsurf, Copilot, Cline) — each in its native format.
 */
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { loadTools } from "./catalog.js";
import { validateRelease } from "./release.js";
import { checkDependencies } from "./dependency.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

export interface DoctorIssue {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
  fix?: string;
}

function which(cmd: string): boolean {
  return spawnSync(`command -v ${cmd}`, { shell: true }).status === 0;
}

function installedCount(): { total: number; installed: string[]; missing: string[] } {
  const tools = loadTools();
  const installed = tools.filter((t) => which(t.name)).map((t) => t.name);
  return { total: tools.length, installed, missing: tools.map((t) => t.name).filter((n) => !installed.includes(n)) };
}

export function runDoctor(): void {
  console.log("BlitzStrike doctor — environment health check\n");
  const issues: DoctorIssue[] = [];

  const bunOk = which("bun") || which("node");
  issues.push({
    name: "Runtime (bun/node)",
    status: bunOk ? "ok" : "fail",
    detail: bunOk ? `node ${process.version}` : "neither bun nor node found",
    fix: bunOk ? undefined : "install bun: curl -fsSL https://bun.sh/install | bash",
  });

  const { total, installed, missing } = installedCount();
  const ratio = installed.length / total;
  issues.push({
    name: "Security tools catalog",
    status: ratio >= 0.4 ? "ok" : ratio >= 0.2 ? "warn" : "fail",
    detail: `${installed.length}/${total} installed, ${missing.length} on-demand`,
    fix: "install on-demand via the ensure_tool MCP tool, or `blitzstrike doctor` again after installing",
  });

  const fofa = Boolean(process.env.FOFA_EMAIL && process.env.FOFA_KEY);
  issues.push({
    name: "FOFA credentials",
    status: fofa ? "ok" : "warn",
    detail: fofa ? "set" : "FOFA_EMAIL/FOFA_KEY not set",
    fix: fofa ? undefined : "export FOFA_EMAIL=... && export FOFA_KEY=... (enables fofa_search)",
  });

  const dataOk = existsSync(join(ROOT, "chains.json")) && existsSync(join(ROOT, "tools-catalog.json"));
  issues.push({
    name: "Data layers (chains + tools-catalog)",
    status: dataOk ? "ok" : "fail",
    detail: dataOk ? "present" : "chains.json or tools-catalog.json missing",
    fix: dataOk ? undefined : "re-install blitzstrike",
  });

  // Release metadata consistency (package.json vs CHANGELOG).
  const release = validateRelease();
  issues.push({
    name: "Release metadata",
    status: release.consistent ? "ok" : "fail",
    detail: release.consistent ? `v${release.version} consistent` : release.checks.filter((c) => !c.ok && !c.soft).map((c) => c.name).join(", ") || "drift",
    fix: release.consistent ? undefined : "align package.json version with the latest CHANGELOG entry",
  });

  // Dependency security (install-time scripts / git deps).
  const deps = checkDependencies();
  issues.push({
    name: "Dependency surface",
    status: deps.safe ? "ok" : "warn",
    detail: deps.safe ? `${deps.total_dependencies} deps, no install scripts` : `${deps.install_scripts.length} install script(s) + ${deps.git_dependencies.length} git dep(s)`,
    fix: deps.safe ? undefined : "remove install-time scripts and git dependencies",
  });

  const symbol = { ok: "OK  ", warn: "WARN", fail: "FAIL" } as const;
  for (const i of issues) {
    console.log(`${symbol[i.status]}  ${i.name}  ${i.detail}`);
    if (i.fix) console.log(`     fix: ${i.fix}`);
  }

  if (installed.length > 0) {
    console.log(`\nInstalled tools (${installed.length}): ${installed.slice(0, 15).join(", ")}${installed.length > 15 ? ", …" : ""}`);
  }

  const fails = issues.filter((i) => i.status === "fail").length;
  const warns = issues.filter((i) => i.status === "warn").length;
  const verdict = fails > 0 ? "degraded" : warns > 0 ? "ready (some warnings)" : "healthy";
  console.log(`\nBlitzStrike — ${verdict}`);
  if (fails > 0) process.exitCode = 1;
}

// ---------------------------------------------------------------------------
// install: auto-detect every agent CLI + write native config
// ---------------------------------------------------------------------------

/** Resolve the best runnable command for BlitzStrike on this machine.
 *  Priority: global `blitzstrike` binary → `bun run <src>` (source) → compiled dist. */
function resolveCommand(): { command: string; args: string[] } {
  // 1. global binary (npm i -g blitzstrike) — fastest, no network
  if (which("blitzstrike")) return { command: "blitzstrike", args: ["serve", "--mcp"] };
  // 2. source checkout (dev): run via bun
  const src = join(ROOT, "src", "index.ts");
  if (which("bun") && existsSync(src)) return { command: "bun", args: ["run", src, "serve", "--mcp"] };
  // 3. npx — universal zero-install fallback (works even without a global binary)
  if (which("npx")) return { command: "npx", args: ["-y", "blitzstrike", "serve", "--mcp"] };
  // 4. bunx — alternative zero-install
  if (which("bunx")) return { command: "bunx", args: ["blitzstrike", "serve", "--mcp"] };
  // 5. last resort: bundled dist via bun
  const dist = join(ROOT, "dist", "index.js");
  if (existsSync(dist)) return { command: "bun", args: [dist, "serve", "--mcp"] };
  return { command: "npx", args: ["-y", "blitzstrike", "serve", "--mcp"] };
}

interface AgentTarget {
  name: string;
  /** config path used for detection (may be a dir) */
  detectPath: string;
  /** is the agent installed? (config present OR binary on PATH) */
  installed: () => boolean;
  write: (command: string, args: string[]) => void;
}

function readJson(p: string): Record<string, unknown> | null {
  try { return JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>; } catch { return null; }
}

/** JSON mcpServers-style write (Claude/Cursor/Gemini/Windsurf/Copilot/Cline). */
function jsonMcpServersWrite(p: string): (command: string, args: string[]) => void {
  return (command, args) => {
    const dir = dirname(p);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const existing = readJson(p) ?? {};
    existing.mcpServers = {
      ...(existing.mcpServers ?? {}),
      blitzstrike: { command, args },
    };
    writeFileSync(p, JSON.stringify(existing, null, 2));
  };
}

/** OpenCode: `mcp.<name>` with `type: "local"` + command array, plus agent personas.
 *  Uses the RESOLVED command (global binary first, npx only as fallback) so a
 *  locally-installed build is always preferred over the npm registry. */
function opencodeWrite(p: string): (command: string, args: string[]) => void {
  return (command, args) => {
    const dir = dirname(p);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const existing = readJson(p) ?? {};
    existing.mcp = {
      ...(existing.mcp ?? {}),
      blitzstrike: { type: "local", command: [command, ...args], enabled: true },
    };
    writeFileSync(p, JSON.stringify(existing, null, 2));
    // also install OpenCode agent personas (blitzstrike orchestrator + 3 tier specialists)
    copyOpenCodeAgents();
  };
}

/** Copy the bundled OpenCode agent personas into ~/.config/opencode/agents/. */
function copyOpenCodeAgents(): void {
  const srcDir = join(ROOT, "opencode-agents");
  const dstDir = join(homedir(), ".config", "opencode", "agents");
  if (!existsSync(srcDir)) return;
  if (!existsSync(dstDir)) mkdirSync(dstDir, { recursive: true });
  for (const f of ["Blitz Strike.md", "Blitz.md", "Eagle Eye.md", "Strike.md"]) {
    const src = join(srcDir, f);
    const dst = join(dstDir, f);
    if (existsSync(src)) {
      writeFileSync(dst, readFileSync(src, "utf8"));
    }
  }
}

/** Codex: TOML `[mcp_servers.blitzstrike]`. */
function codexWrite(p: string): (command: string, args: string[]) => void {
  return (command, args) => {
    const dir = dirname(p);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    let existing = existsSync(p) ? readFileSync(p, "utf8") : "";
    if (!existing.trimEnd().endsWith("\n")) existing += "\n";
    // remove any existing blitzstrike block to avoid duplicates
    existing = existing.replace(/^\s*\[mcp_servers\.blitzstrike\]\n(?:^\s*(?:command|args)\s*=.*\n?)*/m, "");
    existing += `\n[mcp_servers.blitzstrike]\ncommand = "${command}"\nargs = ${JSON.stringify(args)}\n`;
    writeFileSync(p, existing);
  };
}

/** Hermes: YAML `mcp_servers:` — merge into existing config, preserve other keys. */
function hermesWrite(p: string): (command: string, args: string[]) => void {
  return (command, args) => {
    const dir = dirname(p);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    let existing = existsSync(p) ? readFileSync(p, "utf8") : "";
    // remove any prior blitzstrike entry (the `  blitzstrike:` key + its indented lines)
    existing = existing.replace(/^  blitzstrike:\n(?:    .*\n?)*/m, "");
    if (!existing.trimEnd().endsWith("\n")) existing += "\n";
    if (existing.includes("mcp_servers:")) {
      // existing mcp_servers key — insert blitzstrike as a child right after it
      const block = `  blitzstrike:\n    command: "${command}"\n    args: ${JSON.stringify(args)}\n`;
      existing = existing.replace(/^(mcp_servers:)\s*\n/m, `$1\n${block}`);
    } else {
      existing += `\nmcp_servers:\n  blitzstrike:\n    command: "${command}"\n    args: ${JSON.stringify(args)}\n`;
    }
    writeFileSync(p, existing);
  };
}

export function detectAgents(): AgentTarget[] {
  const home = homedir();
  const agents: AgentTarget[] = [];

  const claudeJson = join(home, ".claude.json");
  agents.push({
    name: "Claude Code",
    detectPath: claudeJson,
    installed: () => existsSync(claudeJson) || which("claude"),
    write: jsonMcpServersWrite(claudeJson),
  });

  const claudeDesktop = join(home, ".config", "Claude", "claude_desktop_config.json");
  agents.push({
    name: "Claude Desktop",
    detectPath: claudeDesktop,
    installed: () => existsSync(claudeDesktop),
    write: jsonMcpServersWrite(claudeDesktop),
  });

  const cursor = join(home, ".cursor", "mcp.json");
  agents.push({
    name: "Cursor",
    detectPath: cursor,
    installed: () => existsSync(join(home, ".cursor")) || which("cursor"),
    write: jsonMcpServersWrite(cursor),
  });

  const opencode = join(home, ".config", "opencode", "opencode.jsonc");
  agents.push({
    name: "OpenCode",
    detectPath: opencode,
    installed: () => existsSync(join(home, ".config", "opencode")) || which("opencode"),
    write: opencodeWrite(opencode),
  });

  const codex = join(home, ".codex", "config.toml");
  agents.push({
    name: "Codex",
    detectPath: codex,
    installed: () => existsSync(join(home, ".codex")) || which("codex"),
    write: codexWrite(codex),
  });

  const hermes = join(home, ".hermes", "config.yaml");
  agents.push({
    name: "Hermes",
    detectPath: hermes,
    installed: () => existsSync(join(home, ".hermes")) || which("hermes"),
    write: hermesWrite(hermes),
  });

  const gemini = join(home, ".gemini", "settings.json");
  agents.push({
    name: "Gemini CLI",
    detectPath: gemini,
    installed: () => existsSync(join(home, ".gemini")) || which("gemini"),
    write: jsonMcpServersWrite(gemini),
  });

  const windsurf = join(home, ".codeium", "windsurf", "mcp_config.json");
  agents.push({
    name: "Windsurf",
    detectPath: windsurf,
    installed: () => existsSync(join(home, ".codeium")) || which("windsurf"),
    write: jsonMcpServersWrite(windsurf),
  });

  const copilot = join(home, ".copilot", "mcp.json");
  agents.push({
    name: "Copilot",
    detectPath: copilot,
    installed: () => existsSync(join(home, ".copilot")),
    write: jsonMcpServersWrite(copilot),
  });

  const cline = join(home, ".cline", "mcp_settings.json");
  agents.push({
    name: "Cline",
    detectPath: cline,
    installed: () => existsSync(join(home, ".cline")),
    write: jsonMcpServersWrite(cline),
  });

  return agents;
}

export function runInstall(dryRun = false): void {
  const { command, args } = resolveCommand();
  const agents = detectAgents();
  const installed = agents.filter((a) => a.installed());

  console.log("Blitz Strike install — register with every detected agent CLI\n");
  console.log(`Resolved command: ${command} ${args.join(" ")}\n`);

  if (installed.length === 0) {
    console.log("No agent CLI detected. Here's the universal MCP config to paste manually:");
    console.log(JSON.stringify({ mcpServers: { blitzstrike: { command, args } } }, null, 2));
    console.log("\nAgent-specific formats: see docs/installation.md");
    return;
  }

  console.log(`Detected ${installed.length} agent(s): ${installed.map((a) => a.name).join(", ")}\n`);

  if (dryRun) {
    console.log("Dry run — would write to each config (no changes made):");
    for (const a of installed) console.log(`  - ${a.name}  ->  ${a.detectPath}`);
    return;
  }

  let ok = 0;
  for (const a of installed) {
    try {
      a.write(command, args);
      console.log(`OK    ${a.name}  ->  ${a.detectPath}`);
      ok++;
    } catch (e) {
      console.log(`FAIL  ${a.name}  ${String(e)}`);
    }
  }

  console.log(`\nRegistered with ${ok}/${installed.length} agent(s).`);
  console.log("Restart your agent, then call `run_engagement` or any `blitzstrike` tool.");
}

/** Install every catalog tool at once (bulk provisioning). */
export async function runInstallTools(args: string[]): Promise<void> {
  const getArg = (flag: string): string | undefined => {
    const eq = args.find((a) => a.startsWith(`${flag}=`));
    if (eq) return eq.split("=")[1];
    const i = args.indexOf(flag);
    if (i >= 0 && i + 1 < args.length) return args[i + 1];
    return undefined;
  };
  const category = getArg("--category");
  const concurrency = parseInt(getArg("--concurrency") ?? "4", 10);
  const dryRun = args.includes("--dry-run");
  const { installAllTools, loadTools } = await import("./catalog.js");

  if (dryRun) {
    const tools = loadTools();
    const mcp = tools.filter((t) => t.category === "mcp-server");
    const targets = tools.filter((t) => t.category !== "mcp-server" && (!category || t.category === category.toLowerCase()));
    console.log(`Dry run — would attempt ${targets.length} tool(s); ${mcp.length} MCP server(s) skipped (connect, not install):`);
    for (const t of targets) console.log(`  ${t.category.padEnd(11)} ${t.name}`);
    return;
  }

  console.log(`Installing catalog tools${category ? ` (category: ${category})` : ""} — concurrency ${concurrency}\n`);
  const r = await installAllTools({ category, concurrency, onProgress: (name, ok) => console.log(`  ${ok ? "OK  " : "FAIL"} ${name}`) });
  console.log(`\nSummary: ${r.target_count} targets · ${r.installed} newly installed · ${r.already_installed} already present · ${r.failed} failed`);
  const mcp = r.skipped_mcp_servers as string[];
  if (mcp.length) console.log(`Skipped MCP servers (connect them): ${mcp.join(", ")}`);
  const failedList = (r.results as Array<Record<string, unknown>>).filter((x) => x.installed !== true).map((x) => x.name);
  if (failedList.length) console.log(`Failed: ${failedList.join(", ")}`);
}
