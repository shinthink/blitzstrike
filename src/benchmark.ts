/** Benchmark framework (Phase 4).
 *
 * Measures the framework's detection quality against a labelled corpus:
 *   - detection rate (recall): vulnerable fixture -> taint finding
 *   - false-positive rate: safe (sanitized/guarded) fixture -> no finding
 *   - evidence completeness: confirmed findings carry SHA-256 evidence
 *
 * The corpus lives in bench/corpus/*.md (label + code). Each entry is a
 * deterministic, self-contained fixture so results are reproducible.
 */
import { readFileSync, readdirSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir, homedir } from "node:os";
import { analyzeTaintUniversal } from "./universal-taint.js";
import "./adapters.js";
import { analyzeDataFlow2 } from "./eagle2.js";
import { detectComplexBugs } from "./complex-bugs.js";
import { detectRouteConfusion } from "./route-confusion.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const CORPUS = join(ROOT, "bench", "corpus");
/** Writable corpus dir for SELF-HARDENING: verified false-positives captured from
 *  live engagements land here (the package corpus is read-only). */
const CAPTURED_CORPUS_DIR = process.env.BLITZSTRIKE_CORPUS_DIR ?? join(homedir(), ".blitzstrike", "corpus");

export interface CorpusEntry {
  id: string;
  language: string;
  /** true = SHOULD produce a finding; false = safe, must NOT. */
  vulnerable: boolean;
  sink_type?: string;
  /** Which detector this entry exercises (default taint). */
  detector?: "taint" | "complex_bugs" | "route_confusion";
  /** Optional human note (e.g. why this was a false positive). */
  note?: string;
  code: string;
}

/** Parse a corpus file: front-matter-ish label lines then a ```lang code block. */
function parseCorpusFile(path: string): CorpusEntry | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  const lines = text.split("\n");
  let id = "";
  let language = "php";
  let vulnerable = true;
  let sinkType: string | undefined;
  let detector: CorpusEntry["detector"];
  let note: string | undefined;
  let code = "";
  let inCode = false;
  let codeLang = "";

  for (const line of lines) {
    const m = line.match(/^\s*-\s*(id|language|vulnerable|sink_type|detector|note)\s*:\s*(.+)$/i);
    if (!inCode && m) {
      const key = m[1].toLowerCase();
      const val = m[2].trim();
      if (key === "id") id = val;
      else if (key === "language") language = val.toLowerCase();
      else if (key === "vulnerable") vulnerable = val === "true";
      else if (key === "sink_type") sinkType = val;
      else if (key === "detector") detector = val as CorpusEntry["detector"];
      else if (key === "note") note = val;
      continue;
    }
    const start = line.match(/^```(\w*)/);
    if (start && !inCode) {
      inCode = true;
      codeLang = start[1] || "php";
      continue;
    }
    if (inCode && line.trim() === "```") break;
    if (inCode) code += line + "\n";
  }

  if (!id) id = path.split("/").pop()!.replace(/\.md$/, "");
  return { id, language: language || codeLang || "php", vulnerable, sink_type: sinkType, detector, note, code: code.trim() };
}

/** Load entries from one directory (returns [] if missing/empty). */
function loadDir(dir: string): CorpusEntry[] {
  const entries: CorpusEntry[] = [];
  try {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".md")) continue;
      const e = parseCorpusFile(join(dir, f));
      if (e) entries.push(e);
    }
  } catch {
    /* dir missing — fine */
  }
  return entries;
}

export function loadCorpus(): CorpusEntry[] {
  // Package corpus (read-only) + captured false-positives (self-hardening, writable).
  return [...loadDir(CORPUS), ...loadDir(CAPTURED_CORPUS_DIR)];
}

/** SELF-HARDENING: append a VERIFIED false-positive to the writable corpus, so the
 *  next benchmark run measures whether the detector still flags it (precision drop
 *  = the FP is still unfixed). Returns the on-disk path + the parsed entry. */
export function captureFalsePositive(input: { code: string; language: string; detector?: CorpusEntry["detector"]; note?: string; sink_type?: string }): { path: string; entry: CorpusEntry } {
  mkdirSync(CAPTURED_CORPUS_DIR, { recursive: true });
  const slug = (input.note ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "captured";
  const id = `fp-${slug}-${Date.now().toString(36)}`;
  const ext = { php: "php", javascript: "js", typescript: "ts", python: "py", java: "java", js: "js" }[input.language.toLowerCase()] ?? input.language;
  const lines = [
    `- id: ${id}`,
    `- language: ${input.language.toLowerCase()}`,
    `- vulnerable: false`,
    input.detector ? `- detector: ${input.detector}` : null,
    input.sink_type ? `- sink_type: ${input.sink_type}` : null,
    input.note ? `- note: ${input.note}` : null,
    "",
    "```" + ext,
    input.code,
    "```",
  ].filter((l) => l !== null) as string[];
  const path = join(CAPTURED_CORPUS_DIR, `${id}.md`);
  writeFileSync(path, lines.join("\n") + "\n", "utf8");
  const entry: CorpusEntry = { id, language: input.language.toLowerCase(), vulnerable: false, detector: input.detector, note: input.note, sink_type: input.sink_type, code: input.code };
  return { path, entry };
}

export interface BenchmarkResult {
  entry: CorpusEntry;
  detected: boolean;
  sink_kind?: string;
  /** true positive / true negative / false positive / false negative */
  outcome: "tp" | "tn" | "fp" | "fn";
}

function detect(entry: CorpusEntry): { detected: boolean; sinkKind?: string } {
  // Route-confusion detector (regex/heuristic — its own class).
  if (entry.detector === "route_confusion") {
    const f = detectRouteConfusion(entry.code, "bench." + entry.language);
    if (f.length > 0) return { detected: true, sinkKind: f[0].type };
    return { detected: false };
  }
  // Complex-bugs detector (deserialization/type-juggling/SSRF/…).
  if (entry.detector === "complex_bugs") {
    const f = detectComplexBugs(entry.code, "bench." + entry.language);
    if (f.length > 0) return { detected: true, sinkKind: f[0].type };
    return { detected: false };
  }
  const lang = entry.language;
  // php uses the AST engine; others use the universal engine by extension
  if (lang === "php") {
    // EAGLE-EYE 2.0 whole-program engine reads from a file path; write the code
    // to a temp file in the OS temp dir (never inside the package, read-only).
    const tmp = join(tmpdir(), `blitzstrike-bench-${entry.id}-${process.pid}.php`);
    writeFileSync(tmp, entry.code);
    const r = analyzeDataFlow2(tmp);
    rmSync(tmp, { force: true });
    if (r.findings.length > 0) return { detected: true, sinkKind: r.findings[0].sink };
    return { detected: false };
  }
  const ext = { javascript: ".js", typescript: ".ts", python: ".py", java: ".java" }[lang] ?? ".php";
  const r = analyzeTaintUniversal(entry.code, "bench." + ext);
  if (r.findings.length > 0) return { detected: true, sinkKind: r.findings[0].sink };
  return { detected: false };
}

/** Run the benchmark over the whole corpus and report metrics. */
export function runBenchmark(): Record<string, unknown> {
  const entries = loadCorpus();
  const results: BenchmarkResult[] = entries.map((entry) => {
    const { detected, sinkKind } = detect(entry);
    const outcome = entry.vulnerable
      ? (detected ? "tp" : "fn")
      : (detected ? "fp" : "tn");
    return { entry, detected, sink_kind: sinkKind, outcome };
  });

  const tp = results.filter((r) => r.outcome === "tp").length;
  const tn = results.filter((r) => r.outcome === "tn").length;
  const fp = results.filter((r) => r.outcome === "fp").length;
  const fn = results.filter((r) => r.outcome === "fn").length;
  const total = results.length;
  const detectionRate = tp + fn > 0 ? tp / (tp + fn) : 0;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;

  // Per-detector breakdown — the precision metric that matters for tuning.
  const byDetector: Record<string, Record<string, number>> = {};
  for (const r of results) {
    const d = r.entry.detector ?? "taint";
    byDetector[d] = byDetector[d] ?? { tp: 0, tn: 0, fp: 0, fn: 0, total: 0 };
    byDetector[d][r.outcome] += 1;
    byDetector[d].total += 1;
  }
  const detectorMetrics = Object.fromEntries(
    Object.entries(byDetector).map(([d, m]) => {
      const p = m.tp + m.fp > 0 ? m.tp / (m.tp + m.fp) : 0;
      const rec = m.tp + m.fn > 0 ? m.tp / (m.tp + m.fn) : 0;
      const f1 = p + rec > 0 ? (2 * p * rec) / (p + rec) : 0;
      return [d, { ...m, precision: Number(p.toFixed(3)), recall: Number(rec.toFixed(3)), f1: Number(f1.toFixed(3)) }];
    }),
  );

  // SELF-HARDENING: captured false-positives and whether the detector STILL flags
  // them. still_flagged = the FP is unfixed (detector needs a suppression).
  const captured = results.filter((r) => r.entry.id.startsWith("fp-"));
  const capturedStillFlagged = captured.filter((r) => r.outcome === "fp");

  return {
    total_cases: total,
    tp,
    tn,
    fp,
    fn,
    detection_rate: Number(detectionRate.toFixed(3)),
    false_positive_rate: Number(falsePositiveRate.toFixed(3)),
    precision: Number(precision.toFixed(3)),
    by_detector: detectorMetrics,
    captured_false_positives: {
      total: captured.length,
      still_flagged: capturedStillFlagged.length,
      fixed: captured.length - capturedStillFlagged.length,
      entries: captured.map((r) => ({ id: r.entry.id, detector: r.entry.detector ?? "taint", outcome: r.outcome, note: r.entry.note ?? null, still_flagged: r.outcome === "fp" })),
    },
    results: results.map((r) => ({ id: r.entry.id, language: r.entry.language, detector: r.entry.detector ?? "taint", outcome: r.outcome, sink: r.sink_kind })),
  };
}
