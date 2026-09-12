/** HackerOne-grade finding writeup generator.
 *
 * Turns a canonical Finding into the prose a professional report needs:
 * description, root cause, reproduction steps, impact, remediation, and
 * references. Pulls structured content from the technique knowledge base
 * (summary + how_to_test) and the finding's own CWE/severity/evidence.
 */
import type { Finding } from "./finding.js";
import { techniqueLookup } from "./intel.js";

/** chainId -> techniques.json class id. */
const CHAIN_TO_CLASS: Record<string, string> = {
  ssrf: "ssrf",
  ssti: "ssti",
  sql_injection: "sql_injection",
  nosql_injection: "nosql_injection",
  path_traversal: "path_traversal_lfi",
  local_file_inclusion: "path_traversal_lfi",
  open_redirect: "open_redirect",
  reflected_input: "xss",
  xss: "xss",
  stored_xss: "xss",
  cors_misconfiguration: "cors",
  csrf: "csrf",
  jwt: "jwt",
  idor: "idor",
  command_injection: "command_injection",
  xxe: "xxe",
  deserialization: "deserialization",
  file_upload: "file_upload",
  host_header: "host_header",
  subdomain_takeover: "subdomain_takeover",
  prototype_pollution: "prototype_pollution",
  mass_assignment: "mass_assignment",
};

/** Impact prose for the chains Blitz Strike actually emits; generic fallback otherwise. */
const IMPACT: Record<string, string> = {
  ssti: "Remote code execution in the template engine's context — an attacker can execute arbitrary commands on the server, read sensitive files and environment variables, and pivot into the underlying infrastructure (full host compromise).",
  ssrf: "The server fetches an attacker-controlled URL, letting an attacker reach internal-only services (cloud metadata endpoints, databases, admin panels, internal APIs) from inside the network — exfiltrating credentials and pivoting into the internal infrastructure.",
  sql_injection: "Unauthorized read and write of the application database: mass exfiltration of user records, authentication bypass, data tampering, and (depending on DBMS and privileges) command execution on the database host.",
  command_injection: "Arbitrary operating-system command execution on the server — an attacker can run shell commands, read/write files, exfiltrate data, and take full control of the host.",
  xss: "Execution of attacker-controlled JavaScript in a victim's browser within the target's origin (cross-site scripting): session hijacking, credential theft, account takeover.",
  path_traversal: "Arbitrary file read on the server: disclosure of source code, configuration files, credentials, and other secrets that enable further compromise.",
  open_redirect: "Phishing and token/credential theft — a victim who follows a link from the trusted domain is silently redirected to an attacker-controlled site.",
  reflected_input: "Execution of attacker-controlled script in a victim's browser within the target's origin (cross-site scripting): session hijacking, credential theft, account takeover.",
  cors_misconfiguration: "A malicious website can read authenticated responses from the target by making cross-origin requests with the victim's credentials, leaking sensitive user data.",
  missing_security_headers: "Missing security headers weaken the application's defences: response contents may be embedded (no X-Frame-Options), MIME-sniffed (no X-Content-Type-Options), or transmitted over unencrypted channels (no HSTS).",
};

const REMEDIATION: Record<string, string> = {
  ssti: "Treat template input as untrusted: do not pass user input directly into template expressions, sandbox the rendering engine, and use a locked-down allowlist of template functions.",
  ssrf: "Enforce a strict allowlist of outbound hosts/schemes, block link-local and private ranges (169.254.169.254, 10/8, 172.16/12, 192.168/16, ::1), and never let a client supply the fetch target verbatim.",
  sql_injection: "Use parameterized queries / prepared statements exclusively; never concatenate user input into SQL. Apply least-privilege database accounts.",
  command_injection: "Never pass user input to a shell (system/exec/popen/eval); use a safe API with argument arrays (no shell) or a strict allowlist of commands and arguments.",
  xss: "Output-encode all user-controlled data for the surrounding context (HTML/attribute/JS/URL), and set a strong Content-Security-Policy without 'unsafe-inline'.",
  path_traversal: "Resolve and validate file paths against a canonical base directory (realpath + prefix check), and reject any path containing traversal sequences.",
  open_redirect: "Validate redirect targets against an allowlist of trusted hosts, or use relative/indirect redirects with an opaque token.",
  reflected_input: "Output-encode all user-controlled data for the surrounding context (HTML/attribute/JS/URL), and set a strong Content-Security-Policy without 'unsafe-inline'.",
  cors_misconfiguration: "Restrict Access-Control-Allow-Origin to an explicit allowlist (never reflect the request Origin, never '*' with credentials).",
  missing_security_headers: "Add HSTS (with preload), X-Frame-Options/CSP frame-ancestors, X-Content-Type-Options: nosniff, Referrer-Policy, and a Permissions-Policy.",
};

function safeStr(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export interface FindingWriteup {
  description: string;
  root_cause: string;
  reproduction: string[];
  impact: string;
  remediation: string;
  references: string[];
}

export function findingWriteup(f: Finding): FindingWriteup {
  const chainId = f.chain?.id ?? "";
  const clsId = CHAIN_TO_CLASS[chainId] ?? chainId;
  const cls = clsId ? (techniqueLookup(clsId) as Record<string, unknown>) : { found: false };
  const t = cls?.found ? cls : null;

  const chainName = safeStr(f.chain?.name) || safeStr(t?.name) || "a vulnerability";
  const cwe = safeStr(f.classification?.cwe);
  const cweName = safeStr(f.classification?.cwe_name);
  const sourceName = safeStr(f.source?.name);
  const sourceType = safeStr(f.source?.type);
  const sinkType = safeStr(f.sink?.type);
  const sinkSym = safeStr(f.sink?.symbol);
  const target = [safeStr(f.target?.host), safeStr(f.target?.endpoint)].filter(Boolean).join("");

  // description — prefer the technique summary, else a structured fallback.
  const description = safeStr(t?.summary) ||
    `${chainName} was identified${target ? ` on ${target}` : ""}. Attacker-controlled ${sourceType || "input"}` +
    `${sourceName ? ` ('${sourceName}')` : ""} reaches a ${sinkType || "dangerous sink"}` +
    `${sinkSym ? ` ('${sinkSym}')` : ""} without proper neutralization${cweName ? ` (${cweName})` : ""}.`;

  // root cause — synthesize from source/sink.
  const root_cause =
    `The application forwards ${sourceType || "attacker-controlled input"}` +
    `${sourceName ? ` from '${sourceName}'` : ""} into ${sinkType || "a sensitive operation"}` +
    `${sinkSym ? ` ('${sinkSym}')` : ""} without validating or neutralizing it` +
    (cwe ? `, violating ${cwe}${cweName ? ` (${cweName})` : ""}` : "") + `.`;

  // reproduction — technique how_to_test, then the concrete target + evidence.
  const reproduction: string[] = [];
  const howTo = t?.how_to_test;
  if (Array.isArray(howTo)) for (const step of howTo) reproduction.push(safeStr(step));
  if (target) reproduction.push(`Target the affected endpoint: ${target}.`);
  const evCount = f.evidence?.length ?? 0;
  if (evCount > 0) reproduction.push(`${evCount} evidence record(s) captured (marker + negative control) — see evidence artifacts.`);

  const impact = IMPACT[chainId] || safeStr(t?.summary) ||
    `Exploitation of ${chainName} impacts the confidentiality, integrity, or availability of the application and its data.`;

  const remediation = REMEDIATION[chainId] ||
    `Apply the ${cwe ? cwe : "relevant weakness"} mitigation: validate and neutralize all attacker-controlled input at the sink, enforce least privilege, and add a compensating control at the boundary.`;

  const references: string[] = [];
  if (cwe) {
    const num = cwe.replace(/[^0-9]/g, "");
    if (num) references.push(`https://cwe.mitre.org/data/definitions/${num}.html`);
  }
  if (chainId) {
    const slug = clsId || chainId;
    references.push(`Blitz Strike knowledge base — technique '${slug}'`);
  }

  return { description, root_cause, reproduction, impact, remediation, references };
}
