/** Per-file review harness — the "harness beats model" discipline.
 *
 *  Instead of an autonomous scan that hopes to look in the right place, this
 *  applies a FIXED, deterministic rubric to EVERY enumerated source file and
 *  emits a structured per-file verdict plus a coverage guarantee — nothing is
 *  skipped, and every file is reviewed for the same five signal classes:
 *
 *    entry_points  — unauth request hooks (wp_ajax_nopriv_*, register_rest_route, …)
 *    auth_gates    — authorization checks present (the counter-signal)
 *    sinks         — dangerous source→sink taint (RCE / SQLi / LFI / upload / write)
 *    secrets       — hardcoded credentials / secret formats (CWE-798)
 *    logic_bugs    — client-trusted flags, postMessage, mass assignment, deserialization, …
 *
 *  The aggregate is a full-coverage report: which files were reviewed, which
 *  were clean, and the per-class signal frequency — so a new engagement starts
 *  from a COMPLETE map of the codebase, not a partial scan.
 */
import { readFileSync } from "node:fs";
import { iterSourceFiles, scanFile } from "./scanner.js";
import { detectComplexBugs } from "./complex-bugs.js";

export const REVIEW_RUBRIC = ["entry_points", "auth_gates", "sinks", "secrets", "logic_bugs"] as const;

export interface PerFileReview {
  file: string;
  language: string;
  entry_points: number;
  auth_gates: number;
  sinks: number;
  secrets: number;
  logic_bugs: number;
  findings: Array<{ type: string; line: number; severity: string; evidence: string }>;
  verdict: "reviewed" | "clean" | "unreadable";
}

export interface ReviewHarnessResult {
  root: string;
  rubric: string[];
  files_scanned: number;
  files_clean: number;
  files_with_findings: number;
  coverage: string;
  total_signals: number;
  by_class: Record<string, number>;
  per_file: PerFileReview[];
}

function langFromFile(f: string): string {
  const ext = f.slice(f.lastIndexOf(".")).toLowerCase();
  const map: Record<string, string> = {
    ".php": "php", ".phtml": "php", ".php5": "php",
    ".js": "javascript", ".mjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".py": "python", ".pyw": "python", ".java": "java", ".rb": "ruby",
    ".go": "go", ".rs": "rust", ".sol": "solidity",
  };
  return map[ext] ?? ext.slice(1);
}

const SECRET_TYPES = new Set(["hardcoded_secret"]);

export function reviewHarness(root: string, maxFiles = 5000): ReviewHarnessResult {
  const files = iterSourceFiles(root, maxFiles);
  const per_file: PerFileReview[] = [];
  const by_class: Record<string, number> = {};
  let totalSignals = 0;
  let clean = 0;
  let withFindings = 0;

  for (const f of files) {
    let text = "";
    try {
      text = readFileSync(f, "utf8");
    } catch {
      text = "";
    }
    const sc = scanFile(f);
    const cb = text ? detectComplexBugs(text, f) : [];
    const secrets = cb.filter((x) => SECRET_TYPES.has(x.type));
    const logic = cb.filter((x) => !SECRET_TYPES.has(x.type));

    const findings = [
      ...sc.sinks.map((s) => ({ type: s.class || s.sink, line: s.line, severity: "high", evidence: s.sink })),
      ...secrets.map((x) => ({ type: x.type, line: x.line, severity: x.severity, evidence: x.evidence })),
      ...logic.map((x) => ({ type: x.type, line: x.line, severity: x.severity, evidence: x.evidence })),
    ];

    const count = findings.length;
    totalSignals += count;
    if (count === 0 && !sc.error) clean += 1;
    else withFindings += 1;

    for (const fd of findings) by_class[fd.type] = (by_class[fd.type] ?? 0) + 1;

    per_file.push({
      file: f,
      language: langFromFile(f),
      entry_points: sc.endpoints.length,
      auth_gates: sc.auth_gates_present.length,
      sinks: sc.sinks.length,
      secrets: secrets.length,
      logic_bugs: logic.length,
      findings,
      verdict: sc.error ? "unreadable" : count === 0 ? "clean" : "reviewed",
    });
  }

  // Most signal-dense files first, so the LLM triages the interesting ones.
  per_file.sort((a, b) => b.findings.length - a.findings.length || a.file.localeCompare(b.file));

  return {
    root,
    rubric: [...REVIEW_RUBRIC],
    files_scanned: files.length,
    files_clean: clean,
    files_with_findings: withFindings,
    coverage: `${files.length} source files reviewed (100% of enumerated files; vendor/lib/node_modules excluded by policy)`,
    total_signals: totalSignals,
    by_class,
    per_file,
  };
}
