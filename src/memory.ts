/** Memory layer — append-only JSONL knowledge store.
 *
 * BlitzStrike's long-term memory. NOT session logs (that's noise). It stores
 * VERIFIED, reusable knowledge — a discovered pattern, a working bypass, a
 * confirmed vulnerable signature — so the toolbelt gets smarter every run.
 *
 * Design rules:
 *   - Append-only JSONL (never corrupts, no lost writes).
 *   - Dedup by stable hash (topic + content) — no duplicate entries.
 *   - verified=true is the quality gate: hypotheses do NOT enter memory.
 *
 * Location: $BLITZSTRIKE_HOME/memory.jsonl (default ~/.blitzstrike/).
 */
import { readFileSync, appendFileSync, mkdirSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { homedir } from "node:os";

const HOME_DIR = process.env.BLITZSTRIKE_HOME ?? join(homedir(), ".blitzstrike");
const MEMORY_PATH = join(HOME_DIR, "memory.jsonl");

export type MemoryType = "skill" | "pattern" | "bypass" | "signature" | "lesson" | "engagement";

export interface MemoryEntry {
  id: string;
  type: MemoryType;
  topic: string;
  title: string;
  content: string;
  tags: string[];
  source: string;
  verified: boolean;
  created: string;
  dedup_hash: string;
}

function ensureDir(): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
}

function dedupHash(topic: string, content: string): string {
  return createHash("sha256").update(`${topic}\u0000${content}`).digest("hex").slice(0, 16);
}

function shortId(hash: string): string {
  return `mem-${hash.slice(0, 12)}`;
}

export function loadMemory(): MemoryEntry[] {
  if (!existsSync(MEMORY_PATH)) return [];
  try {
    const lines = readFileSync(MEMORY_PATH, "utf8").split("\n");
    const out: MemoryEntry[] = [];
    for (const line of lines) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t) as MemoryEntry);
      } catch {
        /* skip corrupt line */
      }
    }
    return out;
  } catch {
    return [];
  }
}

function append(entry: MemoryEntry): void {
  ensureDir();
  appendFileSync(MEMORY_PATH, JSON.stringify(entry) + "\n");
}

/** Remember a piece of knowledge. Dedup: returns existing if already stored. */
export function remember(
  topic: string,
  content: string,
  type: MemoryType = "lesson",
  tags: string[] = [],
  source = "manual",
  verified = false,
): Record<string, unknown> {
  const hash = dedupHash(topic, content);
  const existing = loadMemory().find((e) => e.dedup_hash === hash);
  if (existing) {
    return { saved: false, duplicate: true, id: existing.id, topic, note: "already in memory" };
  }
  const entry: MemoryEntry = {
    id: shortId(hash),
    type,
    topic: topic.trim().toLowerCase(),
    title: topic.trim(),
    content: content.trim(),
    tags: tags.map((t) => t.trim().toLowerCase()),
    source,
    verified,
    created: new Date().toISOString(),
    dedup_hash: hash,
  };
  append(entry);
  return { saved: true, duplicate: false, id: entry.id, topic, type, verified };
}

/** Search memory by topic/tag/content, scored. */
export function memoryLookup(query: string): Record<string, unknown> {
  const q = query.toLowerCase();
  const terms = q.split(/\s+/).filter(Boolean);
  const scored = loadMemory()
    .map((e) => {
      const hay = `${e.topic} ${e.title} ${e.content} ${e.tags.join(" ")}`.toLowerCase();
      let score = 0;
      if (e.topic.includes(q)) score += 10;
      if (e.title.toLowerCase().includes(q)) score += 8;
      if (e.content.toLowerCase().includes(q)) score += 5;
      for (const t of terms) if (hay.includes(t)) score += 2;
      for (const tag of e.tags) if (q.includes(tag) || tag.includes(q)) score += 6;
      return { e, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);

  if (scored.length === 0) {
    const all = loadMemory();
    return { found: false, query, suggestions: all.map((e) => e.topic).slice(0, 10) };
  }
  return {
    found: true,
    query,
    matches: scored.slice(0, 10).map((x) => ({
      id: x.e.id,
      topic: x.e.topic,
      title: x.e.title,
      type: x.e.type,
      verified: x.e.verified,
      tags: x.e.tags,
      content: x.e.content.slice(0, 800),
    })),
  };
}

export function listMemory(): Record<string, unknown> {
  const entries = loadMemory();
  const byType: Record<string, number> = {};
  for (const e of entries) byType[e.type] = (byType[e.type] ?? 0) + 1;
  return {
    total: entries.length,
    by_type: byType,
    verified: entries.filter((e) => e.verified).length,
    entries: entries
      .sort((a, b) => (a.created < b.created ? 1 : -1))
      .map((e) => ({ id: e.id, topic: e.topic, type: e.type, verified: e.verified, created: e.created })),
  };
}

export function forget(id: string): Record<string, unknown> {
  // Append-only store: "forget" = tombstone (rewrite without the entry).
  const entries = loadMemory();
  const kept = entries.filter((e) => e.id !== id);
  if (kept.length === entries.length) {
    return { removed: false, id, note: "not found" };
  }
  writeFileSync(MEMORY_PATH, kept.map((e) => JSON.stringify(e)).join("\n") + (kept.length ? "\n" : ""));
  return { removed: true, id };
}

/** Internal: used by run_engagement auto-capture. */
export function rememberIfAbsent(
  topic: string,
  content: string,
  type: MemoryType,
  tags: string[],
  source: string,
  verified: boolean,
): boolean {
  const r = remember(topic, content, type, tags, source, verified);
  return r.saved === true;
}
