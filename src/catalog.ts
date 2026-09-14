/** Catalog layer — tools + skills knowledge base.
 *
 * Loads tools-catalog.json (tool definitions) and the skills/ directory
 * (playbook markdown), then exposes lookup + auto-install helpers. This is the
 * breadth layer: broad coverage (many tools + many playbooks) without the
 * harness bloat, because MCP tools already provide the execution surface.
 */
import { readFileSync, readdirSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { spawnSync, spawn } from "node:child_process";
import { manualForTool } from "./manuals.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

/** Fixed directory where `git clone`-style installs land (so a bulk install
 * never pollutes the caller's cwd). Relative clone/build commands run here. */
const TOOLS_DIR = process.env.BLITZSTRIKE_TOOLS_DIR ?? join(homedir(), ".blitzstrike", "tools");

/** Toolchains that some install commands implicitly require, with the one-shot
 * command that provisions them when missing (auto-fallback, not a hard error). */
const TOOLCHAIN_INSTALL: Record<string, string> = {
  go: "apt-get install -y golang-go",
  cargo: "apt-get install -y cargo",
  meson: "apt-get install -y meson",
  ninja: "apt-get install -y ninja-build",
};

/** Auto-provision every missing build toolchain (go/cargo/meson/ninja) so
 * `go install` / `cargo install` / `meson build` / `ninja` don't fail with
 * "not found". Returns the list that were missing and got provisioned. */
export function provisionMissingToolchains(): string[] {
  const missing: string[] = [];
  for (const [tc, inst] of Object.entries(TOOLCHAIN_INSTALL)) {
    if (hasCommand(tc)) continue;
    missing.push(tc);
    spawnSync(inst, { shell: true, timeout: 300000, stdio: ["ignore", "pipe", "pipe"] });
  }
  return missing;
}

function hasCommand(cmd: string): boolean {
  // `command -v` is a shell builtin; pass cmd as a positional ($1) so it is never
  // interpolated into the shell text — even a metacharacter-laden cmd stays literal.
  return spawnSync("sh", ["-c", 'command -v "$1" >/dev/null 2>&1', "sh", cmd], { timeout: 8000 }).status === 0;
}

/** Detect which toolchain an install command implicitly needs from its prefix. */
function requiredToolchain(cmd: string): string | null {
  if (/^\s*go\s+install\b/.test(cmd)) return "go";
  if (/^\s*cargo\s+(install|build)\b/.test(cmd)) return "cargo";
  return null;
}

/** Provision a missing toolchain (apt), so `go install`/`cargo install` succeed
 * instead of failing with "go: not found". Provisioned once per process. */
const _provisioned = new Set<string>();
function provisionToolchain(cmd: string): void {
  const tc = requiredToolchain(cmd);
  if (!tc || hasCommand(tc) || _provisioned.has(tc)) return;
  _provisioned.add(tc);
  const inst = TOOLCHAIN_INSTALL[tc];
  if (!inst) return;
  spawnSync(inst, { shell: true, timeout: 300000 });
}

/** Run one install command with two automatic fallbacks:
 *  1. provision the required toolchain (go/cargo) if it is missing;
 *  2. for pip, retry with `--user` when `--break-system-packages` is unsupported
 *     (pip < 23.0 on older distros). */
function runInstallCommand(cmd: string, timeoutMs: number): { status: number | null; output: string } {
  provisionToolchain(cmd);
  let r = spawnSync(cmd, { shell: true, timeout: timeoutMs, cwd: TOOLS_DIR, stdio: ["ignore", "pipe", "pipe"] });
  let output = `${r.stdout?.toString() ?? ""}${r.stderr?.toString() ?? ""}`;
  if (r.status !== 0 && /--break-system-packages/.test(cmd)) {
    const alt = cmd.replace(/--break-system-packages/g, "--user");
    const r2 = spawnSync(alt, { shell: true, timeout: timeoutMs, cwd: TOOLS_DIR, stdio: ["ignore", "pipe", "pipe"] });
    if (r2.status === 0) r = r2;
    output = `${output}\n${r2.stdout?.toString() ?? ""}${r2.stderr?.toString() ?? ""}`;
  }
  return { status: r.status, output };
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ToolFlag {
  name: string;
  type: string;
  description: string;
  required?: boolean;
}

export interface ToolEntry {
  name: string;
  category: string;
  description: string;
  command: string;
  flags: ToolFlag[];
  install: Record<string, string>;
  check_installed: { command: string; exit_code: number; parse_version?: string };
  phase?: string;
  tags?: string[];
  alternatives?: string[];
  requires_root?: boolean;
  pipes?: string[];
  homepage?: string;
  /** MCP-server connection string (npx/SSE/stdio) when this tool is an MCP server, not a one-shot CLI. */
  serve?: string;
  /** When false: this tool needs MANUAL setup (GUI app, C2 framework, versioned
   * binary) — bulk-install reports it as skipped, not failed. true for one-shot
   * installable MCP servers (chrome-devtools-mcp); absent = default installable. */
  installable?: boolean;
  /** Why a tool is manual (surfaced in install-tools skip report). */
  note?: string;
}

export interface SkillEntry {
  name: string;
  file: string;
  description: string;
  size: number;
}

// ---------------------------------------------------------------------------
// Loaders (cached)
// ---------------------------------------------------------------------------

let _toolsCache: ToolEntry[] | null = null;
let _skillsCache: SkillEntry[] | null = null;

export function loadTools(): ToolEntry[] {
  if (_toolsCache) return _toolsCache;
  try {
    const raw = JSON.parse(readFileSync(join(ROOT, "tools-catalog.json"), "utf8"));
    _toolsCache = (raw.tools ?? []) as ToolEntry[];
  } catch {
    _toolsCache = [];
  }
  return _toolsCache;
}

export function loadSkills(): SkillEntry[] {
  if (_skillsCache) return _skillsCache;
  const dir = join(ROOT, "skills");
  const out: SkillEntry[] = [];
  try {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".md")) continue;
      const p = join(dir, f);
      const text = readFileSync(p, "utf8");
      const descMatch = text.match(/^description:\s*(.+)$/m);
      out.push({
        name: f.replace(/\.md$/, ""),
        file: f,
        description: (descMatch?.[1] ?? "").trim().slice(0, 200),
        size: text.length,
      });
    }
  } catch {
    /* no skills dir */
  }
  _skillsCache = out;
  return out;
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

export function toolLookup(name: string): Record<string, unknown> {
  const tools = loadTools();
  const t = tools.find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (!t) {
    return {
      found: false,
      query: name,
      suggestions: tools
        .filter((x) => x.name.includes(name.toLowerCase()) || name.toLowerCase().includes(x.name))
        .slice(0, 5)
        .map((x) => x.name),
    };
  }
  // Attach deep manual when available (fuzzy — e.g. "metasploit" -> msfconsole).
  const manual = manualForTool(t.name);
  const result: Record<string, unknown> = { found: true, tool: t };
  if (manual && manual.content) {
    result.manual = {
      name: manual.name,
      category: manual.category,
      preview: manual.content.slice(0, 1500),
      full_length: manual.content.length,
    };
  } else {
    result.manual = null;
  }
  return result;
}

export function listTools(): Record<string, unknown> {
  const tools = loadTools();
  const byCat: Record<string, string[]> = {};
  for (const t of tools) {
    (byCat[t.category] ??= []).push(t.name);
  }
  return { total: tools.length, categories: byCat, tools: tools.map((t) => ({ name: t.name, category: t.category, description: t.description })) };
}

export function skillLookup(topic: string): Record<string, unknown> {
  const skills = loadSkills();
  const q = topic.toLowerCase();
  const scored = skills
    .map((s) => {
      const hay = `${s.name} ${s.description}`.toLowerCase();
      const nameHit = s.name.includes(q);
      const descHit = s.description.includes(q);
      const wordHit = q.split(/\s+/).filter((w) => w && hay.includes(w)).length;
      return { s, score: (nameHit ? 10 : 0) + (descHit ? 5 : 0) + wordHit * 2 };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);

  if (scored.length === 0) {
    return { found: false, query: topic, suggestions: skills.map((s) => s.name).slice(0, 10) };
  }
  return {
    found: true,
    matches: scored.slice(0, 5).map((x) => ({ name: x.s.name, description: x.s.description, file: x.s.file })),
  };
}

export function listSkills(): Record<string, unknown> {
  const skills = loadSkills();
  return { total: skills.length, skills: skills.map((s) => ({ name: s.name, description: s.description })) };
}

export function readSkill(name: string): Record<string, unknown> {
  const skills = loadSkills();
  const s = skills.find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (!s) return { found: false, query: name };
  try {
    const text = readFileSync(join(ROOT, "skills", s.file), "utf8");
    return { found: true, name: s.name, content: text.slice(0, 12000) };
  } catch {
    return { found: false, query: name, error: "unreadable" };
  }
}

// ---------------------------------------------------------------------------
// Auto-install (catalog-tool installer)
// ---------------------------------------------------------------------------

export function ensureTool(name: string): Record<string, unknown> {
  const tools = loadTools();
  const t = tools.find((x) => x.name.toLowerCase() === name.toLowerCase());
  if (!t) {
    return { found: false, query: name, suggestions: tools.slice(0, 5).map((x) => x.name) };
  }

  // Manual tool (GUI/C2/versioned) — never auto-install, report the note.
  if (t.installable === false) {
    return { name: t.name, installed: false, action: "manual", note: t.note ?? "manual install (GUI/C2/versioned — install by hand)" };
  }

  // check installed: the reliable "not installed" signal is exit 127
  // (command not found from the shell). Any other exit code means the binary
  // EXISTS and RAN — even if it returned 1/2/255 on a help/version flag.
  const check = spawnSync(t.check_installed.command, { shell: true, timeout: 15000 });
  if (check.status !== 127 && check.error === undefined) {
    return { name: t.name, installed: true, action: "none", note: "already installed" };
  }

  // install
  const platform = process.platform;
  const cmd = t.install[platform] ?? t.install.linux;
  if (!cmd) {
    return { name: t.name, installed: false, action: "none", note: `no install command for ${platform}` };
  }
  mkdirSync(TOOLS_DIR, { recursive: true });
  const { status, output } = runInstallCommand(cmd, 300000);
  const ok = status === 0;
  return {
    name: t.name,
    installed: ok,
    action: "install",
    command: cmd,
    output: output.slice(-400),
  };
}

/** Map a chain `tool_hint` (e.g. "sqlmap", "jwt_tool", "nuclei") to a catalog tool
 * name, matching by exact name, a tag, or a fuzzy substring. */
export function toolForHint(hint: string): string | null {
  const tools = loadTools();
  // Normalize by stripping ALL non-alphanumerics (hyphens, underscores, spaces) so
  // "rogue_jndi", "rogue-jndi" and "roguejndi" all resolve to the same tool.
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const q = norm(hint);
  const byName = tools.find((x) => norm(x.name) === q);
  if (byName) return byName.name;
  const byTag = tools.find((x) => (x.tags ?? []).some((t: string) => norm(t) === q));
  if (byTag) return byTag.name;
  const bySub = tools.find((x) => norm(x.name).includes(q) || q.includes(norm(x.name)));
  if (bySub) return bySub.name;
  return null;
}

/** Build the CLI argv for a catalog tool against a target: required flags
 * (the first required string/path flag receives the target), then a positional /
 * unambiguous target-flag fallback for tools with no required flag, then extras.
 * Exported for deterministic testing (no subprocess spawned). */
export function buildCatalogCommand(t: { command: string; flags?: Array<{ name: string; type?: string; required?: boolean }> }, target: string, extraFlags: string[] = []): string[] {
  const args: string[] = [t.command];
  let targetPlaced = false;
  for (const f of t.flags ?? []) {
    if (!f.required) continue;
    if ((f.type === "string" || f.type === "path") && !targetPlaced) {
      args.push(f.name, target);
      targetPlaced = true;
    } else if (f.type === "boolean") {
      args.push(f.name);
    }
  }
  // Fallback: tools with NO required flag still need the target — use an
  // unambiguous target flag (-u/--url/--domain/--target) when the tool defines
  // one, otherwise pass the target positionally. ("-d"/"-l" are deliberately
  // excluded — they are ambiguous across tools, e.g. curl -d = data.)
  if (!targetPlaced) {
    const targetFlag = (t.flags ?? []).find((f) => /^[-]{0,2}(u|url|domain|target)$/i.test(f.name));
    if (targetFlag) args.push(targetFlag.name, target);
    else args.push(target);
  }
  args.push(...extraFlags);
  return args;
}

/** Ensure a catalog tool is installed and run it against a target with the tool's
 * REQUIRED flags (the first required string/path flag receives the target), plus
 * any extra flags. Returns the exit code + capped output. Non-interactive by
 * design — no destructive flags are added beyond the tool's own required flags. */
export function runCatalogTool(hint: string, target: string, extraFlags: string[] = []): Record<string, unknown> {
  const tools = loadTools();
  const name = toolForHint(hint);
  if (!name) return { found: false, query: hint, suggestions: tools.slice(0, 6).map((x) => x.name) };
  const t = tools.find((x) => x.name === name)!;

  const ens = ensureTool(t.name);
  if (!ens.installed) {
    return { found: true, name: t.name, installed: false, note: ens.note ?? "install failed", install: ens.command };
  }

  // MCP servers are long-running daemons, not one-shot CLIs — don't spawn them;
  // return the connection string so the driving agent connects them as an MCP
  // server instead of trying to run them as a subprocess.
  if (t.category === "mcp-server" || (t as { serve?: string }).serve) {
    return {
      found: true,
      name: t.name,
      kind: "mcp-server",
      installed: true,
      connect: (t as { serve?: string }).serve ?? `npx ${t.name}`,
      note: "Run this as an MCP server (stdio/SSE) and connect the agent to it — it is not a one-shot CLI.",
    };
  }

  const args = buildCatalogCommand(t, target, extraFlags);

  // Run the tool DIRECTLY (no shell) so the target is a literal argv element —
  // a malicious target (`example.com; rm -rf /`) must NOT be interpreted by a shell.
  const r = spawnSync(args[0], args.slice(1), { timeout: 90000, maxBuffer: 1024 * 1024 });
  const out = (r.stdout?.toString() ?? "") || (r.stderr?.toString() ?? "");
  return {
    found: true,
    name: t.name,
    installed: true,
    command: args.join(" "),
    exit: r.status,
    output: out.slice(0, 6000),
  };
}

/** Async variant of ensureTool — checks + installs a tool without blocking the
 * event loop, so bulk installs can run in parallel. The shell returns 127 for
 * "command not found" (the reliable not-installed signal). */
export function ensureToolAsync(name: string, timeoutMs = 300000): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const t = loadTools().find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!t) {
      resolve({ found: false, query: name });
      return;
    }
    if (t.installable === false) {
      resolve({ name: t.name, installed: false, action: "manual", note: t.note ?? "manual install (GUI/C2/versioned — install by hand)" });
      return;
    }
    const check = spawn(t.check_installed.command, { shell: true, timeout: 15000 });
    check.on("error", () => {
      /* spawn error -> treat as not installed */
    });
    check.on("close", (code) => {
      if (code !== 127) {
        resolve({ name: t.name, installed: true, action: "none", note: "already installed" });
        return;
      }
      const cmd = t.install[process.platform] ?? t.install.linux;
      if (!cmd) {
        resolve({ name: t.name, installed: false, action: "none", note: "no install command for this platform" });
        return;
      }
      mkdirSync(TOOLS_DIR, { recursive: true });
      provisionToolchain(cmd);
      const inst = spawn(cmd, { shell: true, timeout: timeoutMs, cwd: TOOLS_DIR, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      inst.stdout?.on("data", (d: Buffer) => {
        out += d.toString();
      });
      inst.stderr?.on("data", (d: Buffer) => {
        out += d.toString();
      });
      inst.on("error", (e) => resolve({ name: t.name, installed: false, action: "install", error: String(e) }));
      inst.on("close", (icode) => {
        if (icode === 0) {
          resolve({ name: t.name, installed: true, action: "install", command: cmd, output: out.slice(-400) });
          return;
        }
        // pip fallback: `--break-system-packages` unsupported on pip < 23 -> retry `--user`.
        if (/--break-system-packages/.test(cmd)) {
          const alt = cmd.replace(/--break-system-packages/g, "--user");
          const r2 = spawn(alt, { shell: true, timeout: timeoutMs, cwd: TOOLS_DIR, stdio: ["ignore", "pipe", "pipe"] });
          let out2 = "";
          r2.stdout?.on("data", (d: Buffer) => {
            out2 += d.toString();
          });
          r2.stderr?.on("data", (d: Buffer) => {
            out2 += d.toString();
          });
          r2.on("error", (e) => resolve({ name: t.name, installed: false, action: "install", error: String(e) }));
          r2.on("close", (i2) => resolve({ name: t.name, installed: i2 === 0, action: "install", command: alt, output: out2.slice(-400) }));
          return;
        }
        resolve({ name: t.name, installed: false, action: "install", command: cmd, output: out.slice(-400) });
      });
    });
  });
}

/** Install every catalog tool (including one-shot-installable MCP servers) in
 * parallel (bounded concurrency). Tools flagged `installable: false` (GUI apps,
 * C2 frameworks, versioned binaries) are reported but not installed — they need
 * manual setup. Returns a summary + per-tool result. */
export async function installAllTools(opts: { concurrency?: number; category?: string; onProgress?: (name: string, ok: boolean) => void } = {}): Promise<Record<string, unknown>> {
  const tools = loadTools();
  const skippedManual = tools.filter((t) => t.installable === false).map((t) => t.name);
  const cat = opts.category?.toLowerCase();
  const targets = tools.filter((t) => t.installable !== false && (!cat || t.category === cat));
  const concurrency = Math.max(1, opts.concurrency ?? 4);

  const results: Array<Record<string, unknown>> = [];
  let idx = 0;
  async function worker(): Promise<void> {
    while (idx < targets.length) {
      const t = targets[idx++];
      const r = await ensureToolAsync(t.name);
      results.push(r);
      opts.onProgress?.(t.name, r.installed === true);
    }
  }
  const workers = Math.min(concurrency, Math.max(1, targets.length));
  await Promise.all(Array.from({ length: workers }, () => worker()));

  const installed = results.filter((r) => r.installed === true && r.action === "install").length;
  const already = results.filter((r) => r.installed === true && r.action === "none").length;
  const failed = results.filter((r) => r.installed !== true).length;
  return {
    target_count: targets.length,
    installed,
    already_installed: already,
    failed,
    skipped_manual: skippedManual,
    results,
  };
}
