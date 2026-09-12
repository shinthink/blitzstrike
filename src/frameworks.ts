/** Framework Intelligence (Phase 5) — data-driven framework security knowledge.
 *
 * Loads framework knowledge from intelligence/frameworks.json (a declarative,
 * extensible definition — not hardcoded rules) and exposes three capabilities:
 *
 *   - detectFramework   : heuristic framework detection from source code
 *   - frameworkProfile  : the full framework knowledge (sources/sinks/sanitizers/
 *                         auth/routing/orm/middleware)
 *   - scanFramework     : match a framework's patterns against source lines,
 *                         producing framework-aware source/sink/sanitizer/auth hits
 *
 * Supported frameworks map to the currently-supported languages (PHP/JS/Py/Java):
 *   Laravel, WordPress (PHP); Express, Next.js (JS/TS); Django, FastAPI (Py);
 *   Spring (Java). Rails (Ruby) is intentionally deferred until Ruby support.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const INTEL = join(ROOT, "intelligence");

// ---------------------------------------------------------------------------
// Data shapes (mirrors intelligence/frameworks.json)
// ---------------------------------------------------------------------------

export interface FrameworkPattern {
  pattern: string;
  label: string;
  cwe?: string;
}

export interface FrameworkProfile {
  id: string;
  name: string;
  language: string;
  description: string;
  detect: string[];
  sources: FrameworkPattern[];
  sinks: FrameworkPattern[];
  sanitizers: FrameworkPattern[];
  auth: FrameworkPattern[];
  routing: FrameworkPattern[];
  orm: FrameworkPattern[];
  middleware: FrameworkPattern[];
}

interface FrameworksData {
  frameworks: FrameworkProfile[];
}

let cache: FrameworksData | null = null;

function load(): FrameworksData | null {
  if (cache) return cache;
  const p = join(INTEL, "frameworks.json");
  if (!existsSync(p)) return null;
  try {
    cache = JSON.parse(readFileSync(p, "utf8")) as FrameworksData;
    return cache;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** All supported frameworks (id, name, language). */
export function listFrameworks(): Array<{ id: string; name: string; language: string }> {
  const data = load();
  if (!data) return [];
  return data.frameworks.map((f) => ({ id: f.id, name: f.name, language: f.language }));
}

/** Full knowledge profile for a framework (or null if unknown). */
export function frameworkProfile(id: string): FrameworkProfile | null {
  const data = load();
  if (!data) return null;
  return data.frameworks.find((f) => f.id === id) ?? null;
}

export interface FrameworkDetection {
  framework: string | null;
  language: string;
  candidates: Array<{ id: string; name: string; score: number }>;
}

/**
 * Detect the framework of a code snippet, narrowed to the declared language.
 * Score = number of detection signals matched (case-insensitive substring).
 */
export function detectFramework(code: string, language: string): FrameworkDetection {
  const data = load();
  const hay = code.toLowerCase();
  const candidates: Array<{ id: string; name: string; score: number }> = [];
  if (data) {
    for (const f of data.frameworks) {
      if (f.language !== language) continue;
      const score = f.detect.reduce((n, sig) => (hay.includes(sig.toLowerCase()) ? n + 1 : n), 0);
      if (score > 0) candidates.push({ id: f.id, name: f.name, score });
    }
  }
  candidates.sort((a, b) => b.score - a.score);
  return { framework: candidates[0]?.id ?? null, language, candidates };
}

export interface FrameworkScanHit {
  line: number;
  pattern: string;
  label: string;
  cwe?: string;
}

export interface FrameworkScanResult {
  framework: string;
  language: string;
  detected: boolean;
  sources: FrameworkScanHit[];
  sinks: FrameworkScanHit[];
  sanitizers: FrameworkScanHit[];
  auth: FrameworkScanHit[];
  summary: {
    sources: number;
    sinks: number;
    sanitizers: number;
    auth: number;
  };
}

/** Match a framework's patterns against source lines. */
export function scanFramework(code: string, frameworkId: string): FrameworkScanResult {
  const profile = frameworkProfile(frameworkId);
  const empty: FrameworkScanResult = {
    framework: frameworkId,
    language: profile?.language ?? "unknown",
    detected: false,
    sources: [],
    sinks: [],
    sanitizers: [],
    auth: [],
    summary: { sources: 0, sinks: 0, sanitizers: 0, auth: 0 },
  };
  if (!profile) return empty;

  const lines = code.split("\n");
  const scan = (patterns: FrameworkPattern[]): FrameworkScanHit[] => {
    const hits: FrameworkScanHit[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      for (const p of patterns) {
        if (line.includes(p.pattern.toLowerCase())) {
          hits.push({ line: i + 1, pattern: p.pattern, label: p.label, cwe: p.cwe });
        }
      }
    }
    return hits;
  };

  const sources = scan(profile.sources);
  const sinks = scan(profile.sinks);
  const sanitizers = scan(profile.sanitizers);
  const auth = scan(profile.auth);

  return {
    framework: frameworkId,
    language: profile.language,
    detected: true,
    sources,
    sinks,
    sanitizers,
    auth,
    summary: { sources: sources.length, sinks: sinks.length, sanitizers: sanitizers.length, auth: auth.length },
  };
}
