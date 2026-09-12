/** Incremental analysis (Phase 8 / §47) — analyze only changed files.
 *
 * git diff → changed files → (per file) engine analysis. Unchanged files are
 * skipped, which makes Blitz Strike practical for CI: only re-analyze what a
 * commit touched. The full-scan path (run_engagement / enrich_scan) remains the
 * authoritative one; this is a fast incremental pass.
 */
import { execSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeDataFlow2 } from "./eagle2.js";
import { analyzeTaintUniversal, detectLanguage } from "./universal-taint.js";
import "./adapters.js";

const SOURCE_EXTS = [".php", ".phtml", ".js", ".mjs", ".ts", ".tsx", ".py", ".pyw", ".java"];

export interface ChangedFileFinding {
  file: string;
  sink: string;
  line: number;
  category: string;
  cwe?: string;
}

export interface IncrementalResult {
  repo: string;
  base: string;
  head: string;
  changed_files: string[];
  files_scanned: number;
  findings: ChangedFileFinding[];
}

function git(repo: string, args: string): string {
  try {
    return execSync(`git ${args}`, { cwd: repo, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 }).trim();
  } catch {
    return "";
  }
}

/** Analyze only the files changed between two refs. */
export function analyzeChangedFiles(repo: string, base = "HEAD~1", head = "HEAD"): IncrementalResult {
  const changed = git(repo, `diff --name-only ${base} ${head}`)
    .split("\n")
    .filter((f) => f && SOURCE_EXTS.some((e) => f.endsWith(e)));

  const findings: ChangedFileFinding[] = [];
  for (const file of changed) {
    const code = git(repo, `show ${head}:${file}`);
    if (!code) continue;
    const lang = detectLanguage(file)?.language;
    if (lang === "php") {
      // analyzeDataFlow2 reads from a path; write changed content to a temp file.
      const dir = mkdtempSync(join(tmpdir(), "blitz-incr-"));
      const tmp = join(dir, "changed.php");
      writeFileSync(tmp, code);
      try {
        const r = analyzeDataFlow2(tmp);
        for (const f of r.findings) findings.push({ file, sink: f.sink, line: f.sink_line, category: f.category, cwe: f.cwe });
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    } else if (lang) {
      const r = analyzeTaintUniversal(code, file);
      for (const f of r.findings) findings.push({ file, sink: f.sink, line: f.sink_line, category: f.sink, cwe: f.cwe });
    }
  }

  return { repo, base, head, changed_files: changed, files_scanned: changed.length, findings };
}

/** List changed source files (without analysis) — the cheap first step. */
export function changedSourceFiles(repo: string, base = "HEAD~1", head = "HEAD"): string[] {
  return git(repo, `diff --name-only ${base} ${head}`)
    .split("\n")
    .filter((f) => f && SOURCE_EXTS.some((e) => f.endsWith(e)));
}
