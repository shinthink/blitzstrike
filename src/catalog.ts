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
import { spawnSync } from "node:child_process";
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
