/** Compliance mapping — map a CWE to the enterprise frameworks a CISO/auditor
 *  actually cares about: OWASP Top 10 (2021), OWASP ASVS v4.0, PCI DSS v4.0,
 *  ISO 27001:2022 (Annex A). Data-driven (one static table), deterministic.
 *
 *  Every finding already carries a CWE; this layer turns that CWE into the
 *  compliance controls the org must answer to. Used by the report + the
 *  `compliance` tool.
 */

export interface ComplianceMapping {
  cwe: string;
  name: string;
  owasp_top10?: string; // e.g. "A03:2021 Injection"
  asvs?: string[]; // ASVS v4.0 requirement ids
  pci?: string[]; // PCI DSS v4.0 requirement ids
  iso?: string[]; // ISO 27001:2022 Annex A control ids
  nist?: string[]; // NIST SP 800-53 control ids (selected)
}

const CWE_COMPLIANCE: Record<string, Omit<ComplianceMapping, "cwe">> = {
  "79": { name: "Cross-site Scripting (XSS)", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.3"], pci: ["6.5.7"], iso: ["A.8.26"], nist: ["SI-10"] },
  "89": { name: "SQL Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.4"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
  "78": { name: "OS Command Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.8"], pci: ["6.5.1"], iso: ["A.8.9"], nist: ["SI-10"] },
  "94": { name: "Code Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.2.4"], pci: ["6.5.1"], iso: ["A.8.9"], nist: ["SI-10"] },
  "918": { name: "Server-Side Request Forgery (SSRF)", owasp_top10: "A10:2021 SSRF", asvs: ["V5.2.6"], pci: ["6.5.6"], iso: ["A.8.20"], nist: ["SC-7"] },
  "611": { name: "XXE", owasp_top10: "A05:2021 Security Misconfiguration", asvs: ["V5.5.2"], pci: ["6.5.3"], iso: ["A.8.26"], nist: ["SI-10"] },
  "502": { name: "Insecure Deserialization", owasp_top10: "A08:2021 Software and Data Integrity Failures", asvs: ["V5.5.1"], pci: ["6.5.2"], iso: ["A.8.26"], nist: ["SI-10"] },
  "22": { name: "Path Traversal", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V12.3.1"], pci: ["6.5.8"], iso: ["A.8.12"], nist: ["AC-3"] },
  "601": { name: "Open Redirect", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V5.1.5"], pci: ["6.5.9"], iso: ["A.8.20"], nist: ["AC-3"] },
  "434": { name: "Unrestricted File Upload", owasp_top10: "A03:2021 Injection", asvs: ["V12.3.2"], pci: ["6.5.5"], iso: ["A.8.12"], nist: ["SI-10"] },
  "942": { name: "Permissive Cross-Origin Policy (CORS)", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V4.2.2"], pci: ["6.5.9"], iso: ["A.8.20"], nist: ["AC-4"] },
  "287": { name: "Improper Authentication", owasp_top10: "A07:2021 Identification and Authentication Failures", asvs: ["V2.1.1"], pci: ["7.1.1", "8.1.1"], iso: ["A.8.5"], nist: ["IA-2"] },
  "1336": { name: "Server-Side Template Injection (SSTI)", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.12"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
  "915": { name: "Mass Assignment", owasp_top10: "A04:2021 Insecure Design", asvs: ["V5.1.2"], pci: ["6.5.4"], iso: ["A.8.2"], nist: ["AC-3"] },
  "1321": { name: "Prototype Pollution", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.12"], pci: ["6.5.2"], iso: ["A.8.26"], nist: ["SI-10"] },
  "352": { name: "Cross-Site Request Forgery (CSRF)", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V4.2.2"], pci: ["6.5.9"], iso: ["A.8.5"], nist: ["AC-3"] },
  "319": { name: "Cleartext Transmission of Sensitive Information", owasp_top10: "A02:2021 Cryptographic Failures", asvs: ["V9.1.1"], pci: ["4.1.1"], iso: ["A.8.24"], nist: ["SC-8"] },
  "693": { name: "Protection Mechanism Failure", owasp_top10: "A05:2021 Security Misconfiguration", asvs: ["V14.2.1"], pci: ["6.5.x"], iso: ["A.8.8"], nist: ["SI-2"] },
  "200": { name: "Exposure of Sensitive Information", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V7.4.1"], pci: ["6.5.x"], iso: ["A.8.11"], nist: ["AC-4"] },
  "862": { name: "Missing Authorization", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V4.1.1"], pci: ["7.1.1"], iso: ["A.8.2"], nist: ["AC-3"] },
  "639": { name: "Insecure Direct Object Reference (IDOR)", owasp_top10: "A01:2021 Broken Access Control", asvs: ["V4.1.2"], pci: ["7.1.1"], iso: ["A.8.2"], nist: ["AC-3"] },
  "640": { name: "Weak Password Recovery", owasp_top10: "A07:2021 Identification and Authentication Failures", asvs: ["V2.5.2"], pci: ["8.3.6"], iso: ["A.8.5"], nist: ["IA-5"] },
  "798": { name: "Hard-coded Credentials", owasp_top10: "A07:2021 Identification and Authentication Failures", asvs: ["V2.10.4"], pci: ["8.3.8"], iso: ["A.8.5"], nist: ["IA-5"] },
  "327": { name: "Weak Cryptography", owasp_top10: "A02:2021 Cryptographic Failures", asvs: ["V6.2.1"], pci: ["3.5.1"], iso: ["A.8.24"], nist: ["SC-13"] },
  "306": { name: "Missing Authentication for Critical Function", owasp_top10: "A07:2021 Identification and Authentication Failures", asvs: ["V1.2.1"], pci: ["8.1.1"], iso: ["A.8.5"], nist: ["IA-2"] },
  "90": { name: "LDAP Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.7"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
  "93": { name: "CRLF Injection / HTTP Response Splitting", owasp_top10: "A03:2021 Injection", asvs: ["V5.2.3"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
  "98": { name: "PHP Remote File Inclusion", owasp_top10: "A03:2021 Injection", asvs: ["V12.3.1"], pci: ["6.5.8"], iso: ["A.8.12"], nist: ["SI-10"] },
  "347": { name: "Improper Verification of Cryptographic Signature (JWT)", owasp_top10: "A07:2021 Identification and Authentication Failures", asvs: ["V2.9.1"], pci: ["8.1.1"], iso: ["A.8.5"], nist: ["IA-2"] },
  "643": { name: "XPath Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.3.10"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
  "644": { name: "HTTP Header Injection", owasp_top10: "A03:2021 Injection", asvs: ["V5.2.3"], pci: ["6.5.1"], iso: ["A.8.26"], nist: ["SI-10"] },
};

/** Map a CWE id (with or without the "CWE-" prefix) to its compliance controls. */
export function complianceMap(cwe: string): ComplianceMapping | null {
  const id = (cwe ?? "").toUpperCase().replace(/^CWE-?/, "");
  const m = CWE_COMPLIANCE[id];
  if (!m) return null;
  return { cwe: `CWE-${id}`, ...m };
}

export interface ComplianceSummary {
  total_mapped: number;
  total_unmapped: number;
  by_owasp: Record<string, number>;
  by_asvs: Record<string, number>;
  by_pci: Record<string, number>;
  by_iso: Record<string, number>;
  by_nist: Record<string, number>;
  mappings: Array<{ cwe: string; name: string; owasp_top10: string | null; asvs: string[]; pci: string[]; iso: string[]; nist: string[] }>;
}

/** Aggregate compliance across a list of CWE ids (e.g. from findings). */
export function complianceSummary(cwes: Array<string | null | undefined>): ComplianceSummary {
  const by_owasp: Record<string, number> = {};
  const by_asvs: Record<string, number> = {};
  const by_pci: Record<string, number> = {};
  const by_iso: Record<string, number> = {};
  const by_nist: Record<string, number> = {};
  const mappings: ComplianceSummary["mappings"] = [];
  let mapped = 0;
  let unmapped = 0;
  for (const cwe of cwes) {
    if (!cwe) { unmapped += 1; continue; }
    const m = complianceMap(cwe);
    if (!m) { unmapped += 1; continue; }
    mapped += 1;
    if (m.owasp_top10) by_owasp[m.owasp_top10] = (by_owasp[m.owasp_top10] ?? 0) + 1;
    for (const a of m.asvs ?? []) by_asvs[a] = (by_asvs[a] ?? 0) + 1;
    for (const p of m.pci ?? []) by_pci[p] = (by_pci[p] ?? 0) + 1;
    for (const i of m.iso ?? []) by_iso[i] = (by_iso[i] ?? 0) + 1;
    for (const n of m.nist ?? []) by_nist[n] = (by_nist[n] ?? 0) + 1;
    if (!mappings.some((x) => x.cwe === m.cwe)) {
      mappings.push({ cwe: m.cwe, name: m.name, owasp_top10: m.owasp_top10 ?? null, asvs: m.asvs ?? [], pci: m.pci ?? [], iso: m.iso ?? [], nist: m.nist ?? [] });
    }
  }
  mappings.sort((a, b) => a.cwe.localeCompare(b.cwe));
  return { total_mapped: mapped, total_unmapped: unmapped, by_owasp, by_asvs, by_pci, by_iso, by_nist, mappings };
}
