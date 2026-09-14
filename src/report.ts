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
import { complianceSummary } from "./compliance.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

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
  /** Findings with zero evidence records — evidence-first violations. */
  evidence_less_findings: number;
}

function summarize(findings: Finding[]): ReportSummary {
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  let evidenceArtifacts = 0;
  let evidenceLess = 0;
  for (const f of findings) {
    byStatus[f.status ?? "detected"] = (byStatus[f.status ?? "detected"] ?? 0) + 1;
    const sev = f.classification?.severity ?? "informational";
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    const arts = f.evidence?.reduce((n, e) => n + (e.artifacts?.length ?? 0), 0) ?? 0;
    evidenceArtifacts += arts;
    if ((f.evidence ?? []).length === 0) evidenceLess += 1;
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
    evidence_less_findings: evidenceLess,
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

  if (summary.evidence_less_findings > 0) {
    const evLess = findings.filter((f) => (f.evidence ?? []).length === 0).map((f) => f.id).join(", ");
    lines.push(
      `> ⚠️ **Evidence-first violation:** **${summary.evidence_less_findings}** finding(s) carry NO evidence artifacts (${evLess}). ` +
      `Detection is not proof — every finding must carry the observed artifact (headers, URL, response body). Attach evidence via finding_attach_evidence before finalizing.`,
    );
    lines.push("");
  }

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

  // 6. Compliance Mapping — the frameworks a CISO/auditor must answer to.
  lines.push("## 6. Compliance Mapping");
  lines.push("");
  const comp = complianceSummary(findings.map((f) => f.classification?.cwe ?? null));
  if (comp.total_mapped === 0) {
    lines.push("No CWE-tagged findings to map.");
  } else {
    lines.push("Maps each finding's CWE to OWASP Top 10 (2021), OWASP ASVS v4.0, PCI DSS v4.0, ISO 27001:2022 (Annex A), and NIST SP 800-53.");
    lines.push("");
    for (const m of comp.mappings) {
      lines.push(`- **${m.cwe}** ${m.name}`);
      if (m.owasp_top10) lines.push(`  - OWASP Top 10: \`${m.owasp_top10}\``);
      if (m.asvs.length) lines.push(`  - ASVS v4.0: \`${m.asvs.join(", ")}\``);
      if (m.pci.length) lines.push(`  - PCI DSS v4.0: \`${m.pci.join(", ")}\``);
      if (m.iso.length) lines.push(`  - ISO 27001:2022: \`${m.iso.join(", ")}\``);
      if (m.nist.length) lines.push(`  - NIST 800-53: \`${m.nist.join(", ")}\``);
    }
    if (comp.total_unmapped > 0) {
      lines.push("");
      lines.push(`_${comp.total_unmapped} finding(s) had no CWE and were not mapped._`);
    }
  }
  lines.push("");

  // 7. Recommendations
  lines.push("## 7. Recommendations");
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

  // 8. Appendix — hypotheses + false positives
  lines.push("## 8. Appendix");
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

// ---------------------------------------------------------------------------
// Persistence — write the report to a `reports/` directory so an engagement
// produces an on-disk .md/.json deliverable, not just an in-memory string.
// ---------------------------------------------------------------------------

const REPORT_DIR = process.env.BLITZSTRIKE_REPORT_DIR ?? join(homedir(), ".blitzstrike", "reports");

/** Sanitize a title/scope into a filename-safe slug. */
function slugify(s: string): string {
  const slug = s
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/\./g, "_")
    .slice(0, 60);
  return slug || "engagement";
}

/** Write the report content to the reports dir. Returns the on-disk path. */
export function saveReport(content: string, opts: ReportOptions & { format?: "markdown" | "json" } = {}): { path: string; dir: string; filename: string } {
  mkdirSync(REPORT_DIR, { recursive: true });
  const slug = slugify(opts.scope ?? opts.title ?? "engagement");
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const ext = opts.format === "json" ? "json" : "md";
  const filename = `${slug}-${ts}.${ext}`;
  const path = join(REPORT_DIR, filename);
  writeFileSync(path, content, "utf8");
  return { path, dir: REPORT_DIR, filename };
}
