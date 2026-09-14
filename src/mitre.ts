/** MITRE ATT&CK mapping — deterministic class → technique(s) table.
 *
 *  Every detector class maps to the ATT&CK Enterprise technique(s) a real
 *  adversary uses to achieve that outcome, so a finding is reported with its
 *  technique (e.g. SQLi → T1190 Exploit Public-Facing Application). Derived
 *  from a fixed table, not hardcoded per-engagement.
 */

export interface MitreEntry {
  id: string;
  name: string;
  tactic: string;
}

/** class id → ATT&CK technique(s). Most-relevant technique first. */
export const MITRE_MAP: Record<string, MitreEntry[]> = {
  sql_injection: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  ssti: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  command_injection: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  nosql_injection: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  host_header: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Credential Access" }],
  postmessage_no_origin_check: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Collection" }],
  client_trusted_flag: [{ id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" }],
  deserialization: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  xxe: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  file_upload: [{ id: "T1505", name: "Server Software Component", tactic: "Persistence" }, { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  priv_esc: [{ id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" }, { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" }],
  path_confusion: [{ id: "T1005", name: "Data from Local System", tactic: "Collection" }, { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
  ssrf: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }, { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" }],
  mass_assignment: [{ id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }],
  missing_authz: [{ id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }, { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" }],
  type_juggling: [{ id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }],
  hardcoded_secret: [{ id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" }, { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }],
  prototype_pollution: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  crlf_injection: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Credential Access" }],
  missing_nonce: [{ id: "T1204", name: "User Execution", tactic: "Execution" }],
  wrong_sanitizer: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  llm_injection: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
  graphql_exposure: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
  oauth_misconfig: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Credential Access" }, { id: "T1134", name: "Access Token Manipulation", tactic: "Credential Access" }],
  grpc_reflection: [{ id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" }],
  dependency_confusion: [{ id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" }],
  ml_supply_chain: [{ id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access" }],
  rust_unsafe: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  rust_format_string: [{ id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  jwt_alg_confusion: [{ id: "T1134", name: "Access Token Manipulation", tactic: "Credential Access" }, { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" }],
  cache_deception: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Credential Access" }],
  cors_misconfiguration: [{ id: "T1557", name: "Man-in-the-Middle", tactic: "Credential Access" }],
  xss: [{ id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" }, { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" }],
  subdomain_takeover: [{ id: "T1584", name: "Compromise Infrastructure", tactic: "Resource Development" }],
  open_redirect: [{ id: "T1189", name: "Drive-by Compromise", tactic: "Initial Access" }],
  toctou: [{ id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" }],
  second_order: [{ id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" }],
};

/** Look up the ATT&CK technique(s) for a detector class (canonicalize the id). */
export function mitreLookup(type: string): MitreEntry[] {
  return MITRE_MAP[type?.toLowerCase()] ?? [];
}

/** All MITRE-mapped classes (for the agent to know what is mapped). */
export function listMitreMap(): Array<{ type: string; mitre: MitreEntry[] }> {
  return Object.entries(MITRE_MAP).map(([type, mitre]) => ({ type, mitre }));
}
