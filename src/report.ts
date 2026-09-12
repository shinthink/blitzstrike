/** Reproducible report generator (§38 "Reproducible reports").
 *
 * Emits a deterministic, machine-readable report from a list of canonical
 * Findings. Every report is reproducible: same findings + same build metadata
 * -> byte-identical output (timestamps excluded by default). Two formats:
 * markdown (human) and JSON (machine).
 */
import { sha256 } from "./evidence.js";
import { cvssSeverity } from "./cvss.js";
import type { Finding } from "./finding.js";
import { dedupFindings } from "./dedup.js";

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

function severityLabel(sev: string): string {
  const s = sev.toUpperCase();
  if (s === "CRITICAL") return "🔴 CRITICAL";
  if (s === "HIGH") return "🟠 HIGH";
  if (s === "MEDIUM") return "🟡 MEDIUM";
  if (s === "LOW") return "🔵 LOW";
  return "⚪ INFORMATIONAL";
}

export function reportMarkdown(findings: Finding[], opts: ReportOptions = {}): string {
  const summary = summarize(findings);
  const lines: string[] = [];
  lines.push(`# ${opts.title ?? "Blitz Strike — Security Assessment Report"}`);
  lines.push("");
  lines.push(`- Scope: ${opts.scope ?? "(unset)"}`);
  lines.push(`- Blitz Strike version: ${opts.version ?? "unknown"}`);
  if (opts.include_timestamp) lines.push(`- Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total findings | ${summary.total_findings} |`);
  lines.push(`| Unique root causes | ${summary.unique_root_causes} |`);
  lines.push(`| Confirmed | ${summary.confirmed} |`);
  lines.push(`| False positives | ${summary.false_positives} |`);
  lines.push(`| Evidence artifacts | ${summary.evidence_artifacts} |`);
  lines.push("");
  lines.push("### By status");
  lines.push("");
  for (const [status, n] of Object.entries(summary.by_status).sort()) {
    lines.push(`- ${status}: ${n}`);
  }
  lines.push("");
  lines.push("### By severity");
  lines.push("");
  for (const [sev, n] of Object.entries(summary.by_severity).sort()) {
    lines.push(`- ${sev}: ${n}`);
  }
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("_No findings._");
    return lines.join("\n") + "\n";
  }
  for (const f of findings) {
    lines.push(`### ${f.id ?? "(no id)"} — ${f.title} [${severityLabel(f.classification?.severity ?? "informational")}]`);
    lines.push("");
    lines.push(`- **Status**: \`${f.status ?? "detected"}\``);
    lines.push(`- **Confidence**: ${f.confidence ?? "—"} (${f.confidence_level ?? "unscored"})`);
    if (f.classification?.cwe) lines.push(`- **CWE**: ${f.classification.cwe}`);
    if (f.classification?.cvss_score != null) lines.push(`- **CVSS**: ${f.classification.cvss_score} (${f.classification.cvss_vector ?? ""}) — ${cvssSeverity(f.classification.cvss_score)}`);
    lines.push(`- **Source**: ${f.source?.type} \`${f.source?.name ?? ""}\``);
    lines.push(`- **Sink**: ${f.sink?.type}${f.sink?.symbol ? ` \`${f.sink.symbol}\`` : ""}`);
    if (f.target?.host || f.target?.endpoint) lines.push(`- **Target**: ${[f.target.host, f.target.endpoint].filter(Boolean).join("")}`);
    lines.push(`- **Evidence**: ${f.evidence?.length ?? 0} record(s)`);
    if (f.remediation && Object.keys(f.remediation).length) {
      lines.push(`- **Note**: ${JSON.stringify(f.remediation)}`);
    }
    lines.push("");
  }
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
