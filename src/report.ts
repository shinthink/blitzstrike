/** Reproducible report generator (§38 "Reproducible reports").
 *
 * Emits a deterministic, machine-readable report from a list of canonical
 * Findings. Every report is reproducible: same findings + same build metadata
 * -> byte-identical output (timestamps excluded by default). Two formats:
 * markdown (human) and JSON (machine).
 */
import { sha256 } from "./evidence.js";
import type { Finding } from "./finding.js";
import { dedupFindings } from "./dedup.js";
import { findingWriteup } from "./writeup.js";
import { cvssAssess, type CvssInput } from "./cvss.js";

/** Default CVSS v3.1 metric set per severity band (fallback when a finding has
 *  no explicit CVSS computed), so every finding carries a score AND a vector. */
const SEVERITY_METRICS: Record<string, CvssInput> = {
  critical: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" },
  high: { AV: "N", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "N" },
  medium: { AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "L", I: "L", A: "N" },
  low: { AV: "N", AC: "H", PR: "N", UI: "R", S: "U", C: "L", I: "N", A: "N" },
  informational: { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" },
};

function effectiveCvss(f: Finding): { score: number; vector: string } {
  const score = f.classification?.cvss_score;
  const vector = f.classification?.cvss_vector;
  if (score != null && vector) return { score, vector };
  const metrics = SEVERITY_METRICS[f.classification?.severity ?? "informational"] ?? SEVERITY_METRICS.informational;
  const a = cvssAssess(metrics);
  return { score: score ?? a.score, vector: vector ?? a.vector };
}

export interface ReportOptions {
  /** Engagement title. */
  title?: string;
  /** Scope/target description. */
  scope?: string;
  /** Build/version identifier for reproducibility. */
  version?: string;
  /** Include generation timestamp (defaults false for byte-reproducibility). */
  include_timestamp?: boolean;
}

export interface ReportSummary {
  total_findings: number;
  unique_root_causes: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  confirmed: number;
  false_positives: number;
  evidence_artifacts: number;
}

function summarize(findings: Finding[]): ReportSummary {
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let evidenceArtifacts = 0;
  for (const f of findings) {
    byStatus[f.status ?? "detected"] = (byStatus[f.status ?? "detected"] ?? 0) + 1;
    const sev = f.classification?.severity ?? "informational";
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    evidenceArtifacts += f.evidence?.reduce((n, e) => n + (e.artifacts?.length ?? 0), 0) ?? 0;
  }
  const groups = dedupFindings(findings);
  return {
    total_findings: findings.length,
    unique_root_causes: groups.length,
    by_status: byStatus,
    by_severity: bySeverity,
    confirmed: byStatus["confirmed"] ?? 0,
    false_positives: byStatus["false_positive"] ?? 0,
    evidence_artifacts: evidenceArtifacts,
  };
}

export function reportMarkdown(findings: Finding[], opts: ReportOptions = {}): string {
  const summary = summarize(findings);
  const lines: string[] = [];
  const title = opts.title ?? "Blitz Strike — Security Assessment Report";
  const scope = opts.scope ?? "(unset)";

  lines.push(`# ${title}`);
  lines.push("");

  // 1. Executive summary
  const confirmed = findings.filter((f) => f.status === "confirmed");
  const hypotheses = findings.filter((f) => f.status === "hypothesis" || f.status === "validating");
  const fps = findings.filter((f) => f.status === "false_positive");
  const topFinding = confirmed.length
    ? confirmed.reduce((a, b) => ((a.classification?.cvss_score ?? 0) >= (b.classification?.cvss_score ?? 0) ? a : b))
    : findings[0];

  lines.push("## 1. Executive Summary");
  lines.push("");
  lines.push(
    `This assessment of **${scope}** identified **${summary.total_findings}** finding(s): ` +
    `**${confirmed.length}** confirmed, **${hypotheses.length}** hypothesis/hypotheses pending verification, and ` +
    `**${fps.length}** cleared as false positives, spanning **${summary.unique_root_causes}** unique root cause(s).`,
  );
  lines.push("");
  if (topFinding) {
    const tCvss = effectiveCvss(topFinding);
    lines.push(
      `The highest-severity finding is **${topFinding.title}** ` +
      `(${(topFinding.classification?.severity ?? "informational").toUpperCase()}, CVSS ${tCvss.score}). `,
    );
  }
  lines.push(`Detailed findings, reproduction steps, impact, and remediation follow in section 5.`);
  lines.push("");

  // 2. Scope
  lines.push("## 2. Scope");
  lines.push("");
  lines.push(`- **Target(s):** ${scope}`);
  lines.push(`- **Assessment type:** automated security assessment (reconnaissance → analysis → live verification → report)`);
  lines.push("");

  // 3. Methodology
  lines.push("## 3. Methodology");
  lines.push("");
  lines.push("The engagement followed a deterministic, evidence-first pipeline:");
  lines.push("");
  lines.push("1. **Reconnaissance** — fingerprint, WAF/tech/version detection, crawling, subdomain and API discovery.");
  lines.push("2. **Analysis** — source-to-sink taint/route/complex-bug detection for source; injection/auth/business-logic for live targets.");
  lines.push("3. **Verification** — every candidate validated live with a marker + negative control (and WAF-bypass re-probes); a hit is a HYPOTHESIS until confirmed.");
  lines.push("4. **Report** — findings with derived severity (CVSS), CWE mapping, evidence, and reproduction.");
  lines.push("");

  // 4. Summary of findings
  lines.push("## 4. Summary of Findings");
  lines.push("");
  lines.push("| # | Title | Severity | CVSS | Status | CWE |");
  lines.push("|---|-------|----------|------|--------|-----|");
  if (findings.length === 0) {
    lines.push("| — | _No findings._ | — | — | — | — |");
  } else {
    findings.forEach((f, i) => {
      const sev = f.classification?.severity ?? "informational";
      const cvss = String(effectiveCvss(f).score);
      const cwe = f.classification?.cwe ?? "—";
      lines.push(`| ${i + 1} | ${f.title.replace(/\|/g, "\\|")} | ${sev} | ${cvss} | ${f.status ?? "detected"} | ${cwe} |`);
    });
  }
  lines.push("");

  // 5. Detailed findings
  lines.push("## 5. Detailed Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("_No findings to report._");
  } else {
    findings.forEach((f, i) => {
      const w = findingWriteup(f);
      const sev = (f.classification?.severity ?? "informational").toUpperCase();
      const cvss = effectiveCvss(f);
      const cwe = f.classification?.cwe;
      const cweName = f.classification?.cwe_name;
      const target = [f.target?.host, f.target?.endpoint].filter(Boolean).join("");

      lines.push(`### 5.${i + 1} ${f.id ?? `finding-${i + 1}`} — ${f.title}`);
      lines.push("");
      lines.push("| Field | Value |");
      lines.push("|-------|-------|");
      lines.push(`| Severity | **${sev}** (CVSS ${cvss.score}) |`);
      if (cwe) lines.push(`| CWE | ${cwe}${cweName ? ` — ${cweName}` : ""} |`);
      lines.push(`| Status | \`${f.status ?? "detected"}\` |`);
      lines.push(`| Confidence | ${f.confidence ?? "—"} (${f.confidence_level ?? "unscored"}) |`);
      if (target) lines.push(`| Affected | ${target} |`);
      if (f.source?.type || f.source?.name) lines.push(`| Source | ${f.source?.type ?? ""} \`${f.source?.name ?? ""}\``);
      if (f.sink?.type || f.sink?.symbol) lines.push(`| Sink | ${f.sink?.type ?? ""}${f.sink?.symbol ? ` \`${f.sink.symbol}\`` : ""}`);
      lines.push(`| CVSS vector | \`${cvss.vector}\` |`);
      lines.push("");
      lines.push("**Description**");
      lines.push("");
      lines.push(w.description);
      lines.push("");
      lines.push("**Root Cause**");
      lines.push("");
      lines.push(w.root_cause);
      lines.push("");
      if (w.reproduction.length) {
        lines.push("**Steps to Reproduce**");
        lines.push("");
        w.reproduction.forEach((s, ri) => lines.push(`${ri + 1}. ${s}`));
        lines.push("");
      }
      lines.push("**Impact**");
      lines.push("");
      lines.push(w.impact);
      lines.push("");
      lines.push("**Remediation**");
      lines.push("");
      lines.push(w.remediation);
      lines.push("");
      if (w.references.length) {
        lines.push("**References**");
        lines.push("");
        w.references.forEach((r) => lines.push(`- ${r}`));
        lines.push("");
      }
      lines.push("---");
      lines.push("");
    });
  }

  // 6. Recommendations
  lines.push("## 6. Recommendations");
  lines.push("");
  if (findings.length === 0) {
    lines.push("No findings — no remediation required.");
  } else {
    const ordered = [...findings].sort(
      (a, b) => (b.classification?.cvss_score ?? 0) - (a.classification?.cvss_score ?? 0),
    );
    ordered.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.title}** — ${findingWriteup(f).remediation}`);
    });
  }
  lines.push("");

  // 7. Appendix — hypotheses + false positives
  lines.push("## 7. Appendix");
  lines.push("");
  if (hypotheses.length) {
    lines.push("### Unverified hypotheses (kept for follow-up)");
    lines.push("");
    hypotheses.forEach((f) => lines.push(`- ${f.title} (\`${f.status}\`)`));
    lines.push("");
  }
  if (fps.length) {
    lines.push("### Cleared false positives");
    lines.push("");
    fps.forEach((f) => lines.push(`- ${f.title}`));
    lines.push("");
  }
  lines.push(`- **Blitz Strike version:** ${opts.version ?? "unknown"}`);
  if (opts.include_timestamp) lines.push(`- **Generated:** ${new Date().toISOString()}`);

  return lines.join("\n") + "\n";
}

export function reportJson(findings: Finding[], opts: ReportOptions = {}): string {
  const summary = summarize(findings);
  const payload = {
    title: opts.title ?? "Blitz Strike — Security Assessment Report",
    scope: opts.scope ?? null,
    version: opts.version ?? null,
    summary,
    findings,
    integrity: sha256(JSON.stringify({ summary, findings })),
  };
  return JSON.stringify(payload, null, 2);
}
