/** Manual layer — deep tool reference + playbooks (from kali-pentest, Apache-2.0).
 *
 * This is NOT decoration. It is wired into the engagement flow:
 *   - tool_lookup() auto-attaches the full manual when a catalog tool has one.
 *   - run_engagement() attaches the relevant manual per matched chain's tool_hint.
 *   - read_tool_manual() / read_playbook() expose them directly.
 *
 * 270 tool manuals + 17 playbooks, indexed in manuals-index.json (path map).
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

export interface ManualIndex {
  tools: Record<string, string>;
  playbooks: Record<string, string>;
}

let _indexCache: ManualIndex | null = null;

export function loadManualIndex(): ManualIndex {
  if (_indexCache) return _indexCache;
  try {
    _indexCache = JSON.parse(readFileSync(join(ROOT, "manuals-index.json"), "utf8")) as ManualIndex;
  } catch {
    _indexCache = { tools: {}, playbooks: {} };
  }
  return _indexCache;
}

function readManualFile(relPath: string): string | null {
  const p = join(ROOT, "manuals", relPath);
  if (!existsSync(p)) return null;
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

/** Find a manual by exact or fuzzy tool name. Returns {name, category, content}. */
export function findManual(name: string): Record<string, unknown> {
  const idx = loadManualIndex();
  const tools = idx.tools;
  const key = name.toLowerCase();

  // exact
  if (tools[key]) {
    return { found: true, name: key, path: tools[key], content: readManualFile(tools[key]) ?? "" };
  }
  // ordered fuzzy: (1) exact-prefix match, (2) contains-as-substring, (3) word-boundary.
  const names = Object.keys(tools);
  const prefix = names.filter((t) => t === key || t.startsWith(key + "-") || t.startsWith(key + "."));
  if (prefix.length > 0) {
    const best = prefix[0];
    return { found: true, name: best, path: tools[best], content: readManualFile(tools[best]) ?? "" };
  }
  // substring (word-boundary aware: key must appear as a whole token, not mid-word)
  const contains = names.filter((t) => {
    if (!t.includes(key)) return false;
    // check the key occurrence is a word boundary, not "curl" inside "grpcurl"
    const re = new RegExp(`(^|[^a-z0-9])${escapeRegExp(key)}([^a-z0-9]|$)`);
    return re.test(t);
  });
  if (contains.length > 0) {
    const best = contains[0];
    return { found: true, name: best, path: tools[best], content: readManualFile(tools[best]) ?? "" };
  }
  return { found: false, name, suggestions: names.slice(0, 10) };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function listManuals(): Record<string, unknown> {
  const idx = loadManualIndex();
  return { total_tools: Object.keys(idx.tools).length, total_playbooks: Object.keys(idx.playbooks).length, tools: Object.keys(idx.tools).sort() };
}

export function readPlaybook(name: string): Record<string, unknown> {
  const idx = loadManualIndex();
  const key = name.toLowerCase();
  const matches = Object.keys(idx.playbooks).filter((t) => t.includes(key) || key.includes(t));
  if (matches.length === 0) {
    return { found: false, name, suggestions: Object.keys(idx.playbooks).slice(0, 17) };
  }
  const best = matches[0];
  return { found: true, name: best, content: readManualFile(idx.playbooks[best]) ?? "" };
}

export function listPlaybooks(): Record<string, unknown> {
  const idx = loadManualIndex();
  return { total: Object.keys(idx.playbooks).length, playbooks: Object.keys(idx.playbooks).sort() };
}

/**
 * Map a catalog tool name to a manual (fuzzy). Used by tool_lookup to attach
 * deep reference. Returns null when no manual exists.
 */
export function manualForTool(toolName: string): { name: string; category: string; content: string } | null {
  const idx = loadManualIndex();
  const key = toolName.toLowerCase();
  const exact = idx.tools[key];
  if (exact) {
    const parts = exact.split("/");
    return { name: key, category: parts[0], content: readManualFile(exact) ?? "" };
  }
  // ordered fuzzy (same rules as findManual): prefix then bounded substring.
  const names = Object.keys(idx.tools);
  const prefix = names.filter((t) => t.startsWith(key + "-") || t.startsWith(key + "."));
  if (prefix.length > 0) {
    const best = prefix[0];
    const parts = idx.tools[best].split("/");
    return { name: best, category: parts[0], content: readManualFile(idx.tools[best]) ?? "" };
  }
  const contains = names.filter((t) => {
    if (!t.includes(key)) return false;
    const re = new RegExp(`(^|[^a-z0-9])${escapeRegExp(key)}([^a-z0-9]|$)`);
    return re.test(t);
  });
  if (contains.length > 0) {
    const best = contains[0];
    const parts = idx.tools[best].split("/");
    return { name: best, category: parts[0], content: readManualFile(idx.tools[best]) ?? "" };
  }
  return null;
}
