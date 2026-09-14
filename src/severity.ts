/** Severity calibration — map a detector hit to a platform-neutral priority
 *  tier (P1–P5) + a VRT-style category, so a finding is reported at the severity
 *  a triager would assign — not the detector's raw default. Derived from a
 *  deterministic table, not hardcoded per-engagement.
 */
import { cvssSeverity } from "./cvss.js";

export type PriorityTier = "P1" | "P2" | "P3" | "P4" | "P5";
export type CalibratedSeverity = "critical" | "high" | "medium" | "low" | "informational";

export interface SeverityCalibration {
  type: string;
  vrt_category: string;
  priority: PriorityTier;
  severity: CalibratedSeverity;
  rationale: string;
  /** A CVSS severity hint (cross-ref cvssSeverity) when a CVSS score is supplied. */
  cvss_severity?: string;
}

interface VrtEntry {
  vrt: string;
  priority: PriorityTier;
  severity: CalibratedSeverity;
  rationale: string;
}

// Deterministic, VRT-style mapping: detector type → category + priority tier.
// P1 = critical (RCE/data breach), P2 = high, P3 = medium, P4 = low, P5 = informational.
const VRT_MAP: Record<string, VrtEntry> = {
  sql_injection: { vrt: "injection > sql_injection", priority: "P1", severity: "critical", rationale: "SQL injection reaches sensitive data or enables admin takeover." },
  ssti: { vrt: "injection > server_side_template_injection", priority: "P1", severity: "critical", rationale: "SSTI evaluates expressions server-side → code execution." },
  command_injection: { vrt: "injection > os_command_injection", priority: "P1", severity: "critical", rationale: "User input reaches a shell (system/exec/popen) → arbitrary command execution, full host takeover." },
  deserialization: { vrt: "injection > insecure_deserialization", priority: "P1", severity: "critical", rationale: "Deserialization escalated via a gadget chain → code execution." },
  xxe: { vrt: "injection > xml_external_entity", priority: "P1", severity: "critical", rationale: "XXE reads local files or reaches internal services." },
  file_upload: { vrt: "insecure_design > unrestricted_file_upload", priority: "P1", severity: "critical", rationale: "A web-reachable uploaded file of an executable type → code execution." },
  priv_esc: { vrt: "broken_access_control > privilege_escalation", priority: "P1", severity: "critical", rationale: "A user self-assigns an elevated role → full account/tenant takeover." },
  path_confusion: { vrt: "broken_access_control > path_traversal", priority: "P2", severity: "high", rationale: "Path traversal reads files or writes outside the intended directory; P1 if it reaches an RCE chain." },
  ssrf: { vrt: "insecure_design > server_side_request_forgery", priority: "P2", severity: "high", rationale: "SSRF reaches internal services; P1 when it hits cloud metadata and exfiltrates credentials." },
  mass_assignment: { vrt: "broken_access_control > mass_assignment", priority: "P2", severity: "high", rationale: "Attacker sets a privileged field (role/is_admin) → privilege escalation." },
  missing_authz: { vrt: "broken_access_control > missing_authorization", priority: "P2", severity: "high", rationale: "A state-changing action lacks a capability/ownership check." },
  type_juggling: { vrt: "authentication > authentication_bypass", priority: "P2", severity: "high", rationale: "Loose comparison collapses a hash/secret → authentication bypass." },
  hardcoded_secret: { vrt: "sensitive_data_exposure > hardcoded_credentials", priority: "P2", severity: "high", rationale: "A committed credential is usable by anyone with repo access → account/cloud takeover." },
  prototype_pollution: { vrt: "injection > prototype_pollution", priority: "P2", severity: "high", rationale: "Object prototype corruption can escalate to code execution in gadget-heavy runtimes." },
  crlf_injection: { vrt: "injection > crlf_injection", priority: "P3", severity: "medium", rationale: "Header injection enables cookie poisoning or cache poisoning." },
  missing_nonce: { vrt: "broken_access_control > cross_site_request_forgery", priority: "P3", severity: "medium", rationale: "A state-changing action lacks an anti-CSRF token." },
  wrong_sanitizer: { vrt: "injection > improper_input_validation", priority: "P3", severity: "medium", rationale: "A value sanitized for the wrong context still reaches the sink; severity follows the sink." },
  llm_injection: { vrt: "injection > prompt_injection", priority: "P2", severity: "high", rationale: "Prompt injection can exfiltrate the system prompt, RAG data, or trigger privileged tool use." },
  graphql_exposure: { vrt: "misconfiguration > graphql_introspection", priority: "P4", severity: "low", rationale: "GraphQL introspection exposes the schema but is not directly exploitable." },
  oauth_misconfig: { vrt: "authentication > oauth_misconfiguration", priority: "P2", severity: "high", rationale: "An OAuth/open-redirect misconfiguration can leak authorization codes → account takeover." },
  grpc_reflection: { vrt: "misconfiguration > debug_information_exposure", priority: "P5", severity: "low", rationale: "gRPC reflection exposes the API contract but is not directly exploitable." },
  dependency_confusion: { vrt: "insecure_design > dependency_confusion", priority: "P2", severity: "high", rationale: "An internal package resolves from a squattable public registry → attacker-controlled code in the build." },
  ml_supply_chain: { vrt: "injection > insecure_deserialization", priority: "P1", severity: "critical", rationale: "Untrusted model loading via pickle (torch/joblib/numpy) → arbitrary code execution on load." },
  rust_unsafe: { vrt: "insecure_design > unsafe_memory_operations", priority: "P3", severity: "medium", rationale: "transmute/from_raw_parts/assume_init bypass the borrow checker — a hint that needs bounds verification; memory corruption if attacker-controlled." },
  rust_format_string: { vrt: "injection > format_string_injection", priority: "P2", severity: "high", rationale: "An attacker-controlled format string can read or corrupt memory via format specifiers." },
  jwt_alg_confusion: { vrt: "authentication > jwt_algorithm_confusion", priority: "P1", severity: "critical", rationale: "A verifier accepting HS256 with public-key HMAC lets an attacker forge admin tokens (CVE-2015-9235)." },
  cache_deception: { vrt: "cryptographic_failure > web_cache_deception", priority: "P2", severity: "high", rationale: "Cookie-less static cache keys leak per-session private responses to anonymous callers." },
  cors_misconfiguration: { vrt: "configuration > cors_misconfiguration", priority: "P3", severity: "medium", rationale: "A reflected/wildcard origin with credentials lets any website read authenticated responses cross-origin (CWE-942)." },
  xss: { vrt: "injection > cross_site_scripting", priority: "P2", severity: "high", rationale: "User input into a DOM sink executes script in the victim's origin (CWE-79)." },
  subdomain_takeover: { vrt: "configuration > subdomain_takeover", priority: "P3", severity: "medium", rationale: "A dangling CNAME lets an attacker host content on the victim's subdomain (CWE-404)." },
};

export interface CalibrateInput {
  type?: string;
  /** The detector's reported severity (may be overridden by the table). */
  severity?: string;
  /** Optional CVSS base score (0–10) for a cross-referenced severity. */
  cvss?: number;
  /** Optional: a note that the finding is informational-only. */
  informational?: boolean;
}

/** Calibrate a finding to a VRT-style category + priority tier. */
export function severityCalibrate(input: CalibrateInput): SeverityCalibration {
  const type = input.type?.toLowerCase() ?? "";
  const entry = VRT_MAP[type];

  if (input.informational) {
    return {
      type,
      vrt_category: "informational",
      priority: "P5",
      severity: "informational",
      rationale: "Marked informational — excluded from the validity ratio.",
      ...(input.cvss != null ? { cvss_severity: cvssSeverity(input.cvss) } : {}),
    };
  }

  if (!entry) {
    return {
      type,
      vrt_category: "unclassified",
      priority: "P4",
      severity: "low",
      rationale: `No VRT mapping for '${type}'; defaulting to low until classified.`,
      ...(input.cvss != null ? { cvss_severity: cvssSeverity(input.cvss) } : {}),
    };
  }

  return {
    type,
    vrt_category: entry.vrt,
    priority: entry.priority,
    severity: entry.severity,
    rationale: entry.rationale,
    ...(input.cvss != null ? { cvss_severity: cvssSeverity(input.cvss) } : {}),
  };
}

/** All supported VRT mappings (for the agent to know what classes are calibrated). */
export function listSeverityMap(): Array<{ type: string; priority: PriorityTier; vrt: string }> {
  return Object.entries(VRT_MAP).map(([type, e]) => ({ type, priority: e.priority, vrt: e.vrt }));
}
