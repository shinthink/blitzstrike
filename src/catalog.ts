/** Catalog layer — tools + skills knowledge base.
 *
 * Loads tools-catalog.json (tool definitions) and the skills/ directory
 * (playbook markdown), then exposes lookup + auto-install helpers. This is the
 * breadth layer: broad coverage (many tools + many playbooks) without the
 * harness bloat, because MCP tools already provide the execution surface.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, spawn } from "node:child_process";
import { manualForTool } from "./manuals.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

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
  const r = spawnSync(cmd, { shell: true, timeout: 120000 });
  const ok = r.status === 0;
  return {
    name: t.name,
    installed: ok,
    action: "install",
    command: cmd,
    output: (r.stdout?.toString() ?? "").slice(-400) || (r.stderr?.toString() ?? "").slice(-400),
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

  const r = spawnSync(args.join(" "), { shell: true, timeout: 90000, maxBuffer: 1024 * 1024 });
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
export function ensureToolAsync(name: string, timeoutMs = 120000): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const t = loadTools().find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!t) {
      resolve({ found: false, query: name });
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
      const inst = spawn(cmd, { shell: true, timeout: timeoutMs });
      let out = "";
      inst.stdout?.on("data", (d: Buffer) => {
        out += d.toString();
      });
      inst.stderr?.on("data", (d: Buffer) => {
        out += d.toString();
      });
      inst.on("error", (e) => resolve({ name: t.name, installed: false, action: "install", error: String(e) }));
      inst.on("close", (icode) => {
        resolve({ name: t.name, installed: icode === 0, action: "install", command: cmd, output: out.slice(-400) });
      });
    });
  });
}

/** Install every non-MCP-server catalog tool in parallel (bounded concurrency).
 * MCP servers are reported but not installed (they are connected, not run).
 * Returns a summary + per-tool result. */
export async function installAllTools(opts: { concurrency?: number; category?: string; onProgress?: (name: string, ok: boolean) => void } = {}): Promise<Record<string, unknown>> {
  const tools = loadTools();
  const mcp = tools.filter((t) => t.category === "mcp-server").map((t) => t.name);
  const cat = opts.category?.toLowerCase();
  const targets = tools.filter((t) => t.category !== "mcp-server" && (!cat || t.category === cat));
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
    skipped_mcp_servers: mcp,
    results,
  };
}
