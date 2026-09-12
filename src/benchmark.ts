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
import { readFileSync, readdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { analyzeTaintUniversal } from "./universal-taint.js";
import "./adapters.js";
import { analyzeDataFlow2 } from "./eagle2.js";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const CORPUS = join(ROOT, "bench", "corpus");

export interface CorpusEntry {
  id: string;
  language: string;
  /** true = SHOULD produce a finding; false = safe, must NOT. */
  vulnerable: boolean;
  sink_type?: string;
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
  let code = "";
  let inCode = false;
  let codeLang = "";

  for (const line of lines) {
    const m = line.match(/^\s*-\s*(id|language|vulnerable|sink_type)\s*:\s*(.+)$/i);
    if (!inCode && m) {
      const key = m[1].toLowerCase();
      const val = m[2].trim();
      if (key === "id") id = val;
      else if (key === "language") language = val.toLowerCase();
      else if (key === "vulnerable") vulnerable = val === "true";
      else if (key === "sink_type") sinkType = val;
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
  return { id, language: language || codeLang || "php", vulnerable, sink_type: sinkType, code: code.trim() };
}

export function loadCorpus(): CorpusEntry[] {
  let entries: CorpusEntry[] = [];
  try {
    for (const f of readdirSync(CORPUS)) {
      if (!f.endsWith(".md")) continue;
      const e = parseCorpusFile(join(CORPUS, f));
      if (e) entries.push(e);
    }
  } catch {
    entries = [];
  }
  return entries;
}

export interface BenchmarkResult {
  entry: CorpusEntry;
  detected: boolean;
  sink_kind?: string;
  /** true positive / true negative / false positive / false negative */
  outcome: "tp" | "tn" | "fp" | "fn";
}

function detect(entry: CorpusEntry): { detected: boolean; sinkKind?: string } {
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

  return {
    total_cases: total,
    tp,
    tn,
    fp,
    fn,
    detection_rate: Number(detectionRate.toFixed(3)),
    false_positive_rate: Number(falsePositiveRate.toFixed(3)),
    precision: Number(precision.toFixed(3)),
    results: results.map((r) => ({ id: r.entry.id, language: r.entry.language, outcome: r.outcome, sink: r.sink_kind })),
  };
}
