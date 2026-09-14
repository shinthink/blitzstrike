/** Differential security analysis (Phase 4).
 *
 * Compares two versions of a source file (or a git diff) and surfaces only the
 * *security-sensitive* changes — the delta that matters for triage:
 *
 *   - new vulnerability  : a source→sink path present in the new code but not the old
 *   - fixed vulnerability: a path present in the old code but not the new
 *   - new sink           : a dangerous operation added (added line hits a sink)
 *   - new source         : attacker-controlled input added
 *   - sanitizer removed  : a sanitizer line was removed (may expose a sink)
 *   - authorization removed: an auth/nonce gate was removed
 *
 * The engine-based finding diff is authoritative; the line-level signals are
 * granular hints ranked by severity.
 */
import { writeFileSync, rmSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { analyzeDataFlow2 } from "./eagle2.js";
import { analyzeTaintUniversal, detectLanguage } from "./universal-taint.js";
import "./adapters.js";
import { classifySink, classifySource, findSanitizers } from "./dataflow.js";
import { AUTH_GATES } from "./scanner.js";

// ---------------------------------------------------------------------------
// Normalized findings (engine-agnostic)
// ---------------------------------------------------------------------------

interface NormFinding {
  sink: string;
  sink_line: number;
  category: string;
  source?: string;
  cwe?: string;
}

/** Run the appropriate engine on code and return normalized findings. */
function runEngine(code: string, language: string, file: string): NormFinding[] {
  if (language === "php") {
    const dir = mkdtempSync(join(tmpdir(), "blitz-diff-"));
    const tmp = join(dir, "old.php");
    writeFileSync(tmp, code);
    try {
      const r = analyzeDataFlow2(tmp);
      return r.findings.map((f) => ({ sink: f.sink, sink_line: f.sink_line, category: f.category, source: f.source, cwe: f.cwe }));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
  // Non-PHP: analyzeTaintUniversal detects the adapter from the file extension.
  // Ensure the probe filename carries the extension for the declared language
  // (a bare `file` like "target" has none and would resolve to "unknown").
  const extMap: Record<string, string> = { javascript: ".js", typescript: ".ts", python: ".py", java: ".java" };
  const probe = file.includes(".") ? file : `target${extMap[language] ?? ""}`;
  const r = analyzeTaintUniversal(code, probe);
  return r.findings.map((f) => ({ sink: f.sink, sink_line: f.sink_line, category: f.sink, source: f.source_kind, cwe: f.cwe }));
}

// ---------------------------------------------------------------------------
// Line-level diff (LCS)
// ---------------------------------------------------------------------------

interface LineChange {
  line: number;
  text: string;
}

function diffLines(oldText: string, newText: string): { added: LineChange[]; removed: LineChange[] } {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const added: LineChange[] = [];
  const removed: LineChange[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      removed.push({ line: i + 1, text: a[i] });
      i++;
    } else {
      added.push({ line: j + 1, text: b[j] });
      j++;
    }
  }
  while (i < m) {
    removed.push({ line: i + 1, text: a[i] });
    i++;
  }
  while (j < n) {
    added.push({ line: j + 1, text: b[j] });
    j++;
  }
  return { added, removed };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface DiffChange {
  kind: "new_vulnerability" | "fixed_vulnerability" | "new_sink" | "new_source" | "sanitizer_removed" | "authorization_removed";
  severity: "high" | "medium" | "low";
  sink?: string;
  category?: string;
  source?: string;
  cwe?: string;
  line: number;
  detail: string;
}

export interface DifferentialResult {
  language: string;
  changes: DiffChange[];
  summary: {
    new_vulnerabilities: number;
    fixed_vulnerabilities: number;
    new_sinks: number;
    new_sources: number;
    sanitizers_removed: number;
    authorizations_removed: number;
  };
}

export function analyzeDifferential(oldCode: string, newCode: string, language: string, file = "target"): DifferentialResult {
  const changes: DiffChange[] = [];

  // 1. Engine-based finding diff (authoritative).
  const oldFindings = runEngine(oldCode, language, file);
  const newFindings = runEngine(newCode, language, file);
  const key = (f: NormFinding) => `${f.category}|${f.sink}|${f.sink_line}`;
  const oldKeys = new Set(oldFindings.map(key));
  const newKeys = new Set(newFindings.map(key));

  for (const f of newFindings) {
    if (!oldKeys.has(key(f))) {
      changes.push({
        kind: "new_vulnerability",
        severity: "high",
        sink: f.sink,
        category: f.category,
        source: f.source,
        cwe: f.cwe,
        line: f.sink_line,
        detail: `new ${f.category} at line ${f.sink_line} (${f.sink.trim()})`,
      });
    }
  }
  for (const f of oldFindings) {
    if (!newKeys.has(key(f))) {
      changes.push({
        kind: "fixed_vulnerability",
        severity: "low",
        sink: f.sink,
        category: f.category,
        source: f.source,
        cwe: f.cwe,
        line: f.sink_line,
        detail: `removed ${f.category} at line ${f.sink_line} (${f.sink.trim()})`,
      });
    }
  }

  // 2. Line-level signals (granular hints).
  const { added, removed } = diffLines(oldCode, newCode);

  for (const l of added) {
    const sink = classifySink(l.text);
    if (sink) {
      changes.push({
        kind: "new_sink",
        severity: "medium",
        sink: l.text.trim(),
        category: sink.category,
        cwe: sink.cwe,
        line: l.line,
        detail: `added sink ${l.text.trim()} (${sink.category})`,
      });
    }
    const source = classifySource(l.text);
    if (source) {
      changes.push({
        kind: "new_source",
        severity: source.attacker_controlled ? "medium" : "low",
        source: source.label,
        line: l.line,
        detail: `added source ${l.text.trim()} (${source.label})`,
      });
    }
  }

  for (const l of removed) {
    const san = findSanitizers(l.text);
    if (san.length > 0) {
      changes.push({
        kind: "sanitizer_removed",
        severity: "high",
        line: l.line,
        detail: `removed sanitizer ${san.map((s) => s.label).join(", ")} (${l.text.trim()})`,
      });
    }
    const gates = AUTH_GATES.filter((g) => l.text.includes(g));
    if (gates.length > 0) {
      changes.push({
        kind: "authorization_removed",
        severity: "high",
        line: l.line,
        detail: `removed authorization gate ${gates.join(", ")} (${l.text.trim()})`,
      });
    }
  }

  // Order by severity (high first), then line.
  const rank = { high: 0, medium: 1, low: 2 } as const;
  changes.sort((x, y) => rank[x.severity] - rank[y.severity] || x.line - y.line);

  const count = (k: DiffChange["kind"]) => changes.filter((c) => c.kind === k).length;

  return {
    language,
    changes,
    summary: {
      new_vulnerabilities: count("new_vulnerability"),
      fixed_vulnerabilities: count("fixed_vulnerability"),
      new_sinks: count("new_sink"),
      new_sources: count("new_source"),
      sanitizers_removed: count("sanitizer_removed"),
      authorizations_removed: count("authorization_removed"),
    },
  };
}

/** Detect the language of a file path (fallback: infer from extension). */
export function languageOf(file: string): string {
  const adapter = detectLanguage(file);
  return adapter?.language ?? "php";
}

/** Run differential analysis between two file paths. */
export function analyzeDifferentialFiles(oldPath: string, newPath: string, language?: string): DifferentialResult {
  const oldCode = readFileSync(oldPath, "utf8");
  const newCode = readFileSync(newPath, "utf8");
  const lang = language ?? languageOf(newPath);
  return analyzeDifferential(oldCode, newCode, lang, newPath);
}

// ---------------------------------------------------------------------------
// Git diff integration
// ---------------------------------------------------------------------------

export interface GitDiffResult {
  repo: string;
  base: string;
  head: string;
  files: Array<{ file: string; result: DifferentialResult }>;
  total_changes: number;
  security_sensitive: number;
}

const SOURCE_EXTS = [".php", ".phtml", ".php5", ".js", ".mjs", ".ts", ".tsx", ".py", ".pyw", ".java"];

/** Run differential security analysis across a git commit range. */
export function analyzeGitDiff(repo: string, base = "HEAD~1", head = "HEAD"): GitDiffResult {
  const git = (args: string) => {
    try {
      return execFileSync("git", args.split(/\s+/).filter(Boolean), { cwd: repo, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 }).trim();
    } catch {
      return "";
    }
  };

  const changed = git(`diff --name-only ${base} ${head}`)
    .split("\n")
    .filter((f) => f && SOURCE_EXTS.some((e) => f.endsWith(e)));

  const files: Array<{ file: string; result: DifferentialResult }> = [];
  for (const file of changed) {
    const oldCode = git(`show ${base}:${file}`);
    const newCode = git(`show ${head}:${file}`);
    if (!newCode) continue; // file deleted
    const lang = languageOf(file);
    files.push({ file, result: analyzeDifferential(oldCode || "", newCode, lang, file) });
  }

  const total_changes = files.reduce((n, f) => n + f.result.changes.length, 0);
  const security_sensitive = files.reduce((n, f) => n + f.result.changes.filter((c) => c.severity === "high").length, 0);

  return { repo, base, head, files, total_changes, security_sensitive };
}

// ---------------------------------------------------------------------------
// Patch reversal — the 1-day weaponization engine.
//
// A security PATCH is a public disclosure of the vulnerability it fixes. Read
// the delta, find what the patch ADDED to make the code safer (a sanitizer, an
// auth/nonce gate, a parameterized query, input validation) or what it REMOVED
// (a dangerous sink), and REVERSE it: that is the vulnerability in the OLD
// version. Each reversal carries a DERIVED signature to feed variant_scan, so
// you can sweep the install base for unpatched copies of the same bug.
// ---------------------------------------------------------------------------

export type PatchKind = "sanitizer_added" | "authorization_added" | "prepared_statement_added" | "validation_added" | "sink_removed";

export interface PatchFinding {
  kind: PatchKind;
  /** What the OLD version did wrong (the reversed 0-day). */
  old_vuln: string;
  /** How the NEW version fixed it. */
  new_fix: string;
  cwe?: string;
  line: number;
  severity: "high" | "medium";
  detail: string;
  /** DERIVED signature for this patch class. */
  signature: string;
  /** The detector signature to feed variant_scan for mining unpatched copies. */
  mine_signature: string;
}

const PATCH_RANK = { high: 0, medium: 1 } as const;

export function analyzePatch(oldCode: string, newCode: string, language = "php"): Record<string, unknown> {
  const { added, removed } = diffLines(oldCode, newCode);
  const findings: PatchFinding[] = [];

  // ADDED lines = the FIX (what the new version gained → reveals the old 0-day).
  for (const l of added) {
    const sans = findSanitizers(l.text);
    if (sans.length > 0) {
      findings.push({
        kind: "sanitizer_added",
        old_vuln: "raw attacker input reached a sink without escaping",
        new_fix: l.text.trim(),
        severity: "high",
        line: l.line,
        detail: `sanitizer ADDED: ${sans.map((s) => s.label).join(", ")} — the OLD version passed raw input to a sink (sanitization gap).`,
        signature: "patch:sanitizer_added",
        mine_signature: "complex_bugs:wrong_sanitizer",
      });
    }

    const gates = AUTH_GATES.filter((g) => l.text.includes(g));
    if (gates.length > 0) {
      findings.push({
        kind: "authorization_added",
        old_vuln: "missing authorization / nonce check",
        new_fix: l.text.trim(),
        severity: "high",
        line: l.line,
        detail: `authorization gate ADDED: ${gates.join(", ")} — the OLD version performed no auth/nonce check (auth bypass / CSRF).`,
        signature: "patch:authorization_added",
        mine_signature: "complex_bugs:missing_authz",
      });
    }

    if (/->prepare\s*\(|\bprepare\s*\(\s*["']/.test(l.text)) {
      findings.push({
        kind: "prepared_statement_added",
        old_vuln: "raw SQL string interpolation",
        new_fix: l.text.trim(),
        severity: "high",
        line: l.line,
        detail: "parameterized query ADDED — the OLD version concatenated user input into SQL (SQLi).",
        signature: "patch:prepared_statement_added",
        mine_signature: "complex_bugs:wrong_sanitizer",
      });
    }

    if (/preg_match\s*\(\s*["']\/\^|in_array\s*\(\s*\$|ctype_[a-z]+|is_numeric\s*\(|filter_var\s*\(/.test(l.text)) {
      findings.push({
        kind: "validation_added",
        old_vuln: "unvalidated / arbitrary input accepted",
        new_fix: l.text.trim(),
        severity: "medium",
        line: l.line,
        detail: "input validation ADDED — the OLD version accepted arbitrary input (type/format gap).",
        signature: "patch:validation_added",
        mine_signature: "complex_bugs:wrong_sanitizer",
      });
    }
  }

  // REMOVED lines = the VULNERABLE code (a dangerous sink the patch deleted).
  // Only flag when the removed sink was fed by an attacker-controlled source —
  // a benign `echo $x` (literal) is not a reversal signal.
  for (const l of removed) {
    const sink = classifySink(l.text);
    const source = classifySource(l.text);
    if (sink && source && source.attacker_controlled) {
      findings.push({
        kind: "sink_removed",
        old_vuln: `dangerous sink fed by attacker input: ${sink.category}`,
        new_fix: "(removed)",
        cwe: sink.cwe,
        severity: "high",
        line: l.line,
        detail: `sink REMOVED: ${l.text.trim()} (${sink.category}) — the OLD version executed this dangerous operation on attacker input.`,
        signature: `patch:sink_removed:${sink.category}`,
        mine_signature: `taint:${sink.category}`,
      });
    }
  }

  findings.sort((a, b) => PATCH_RANK[a.severity] - PATCH_RANK[b.severity] || a.line - b.line);

  const count = (k: PatchKind) => findings.filter((f) => f.kind === k).length;

  return {
    language,
    reversal_findings: findings.map((f) => ({
      kind: f.kind,
      old_vuln: f.old_vuln,
      new_fix: f.new_fix,
      cwe: f.cwe,
      line: f.line,
      severity: f.severity,
      detail: f.detail,
      signature: f.signature,
      mine_signature: f.mine_signature,
    })),
    summary: {
      sanitizer_added: count("sanitizer_added"),
      authorization_added: count("authorization_added"),
      prepared_statement_added: count("prepared_statement_added"),
      validation_added: count("validation_added"),
      sink_removed: count("sink_removed"),
    },
    interpretation: "Each reversal is the vulnerability REVERSED from the patch: the OLD version had this bug, the NEW version fixed it. Sweep unpatched installs with variant_scan(root, { signature: mine_signature }).",
  };
}

/** Patch reversal between two file paths (old → new). */
export function analyzePatchFiles(oldPath: string, newPath: string, language?: string): Record<string, unknown> {
  const oldCode = readFileSync(oldPath, "utf8");
  const newCode = readFileSync(newPath, "utf8");
  const lang = language ?? languageOf(newPath);
  return analyzePatch(oldCode, newCode, lang);
}
