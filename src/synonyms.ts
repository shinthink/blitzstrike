/** Synonym / alias resolution — map free-form vuln-class terminology to the
 *  canonical detector id. The LLM (or a human) says "IDOR", "BOLA", "SQLi",
 *  "path traversal" — this resolves it to the canonical `missing_authz`,
 *  `sql_injection`, `path_confusion`, etc. so the empirical grounding is
 *  reachable regardless of the wording used. Data-driven, not hardcoded.
 */

/** Alias → canonical detector id. Keys are lowercased, whitespace/underscore/dash
 *  normalized to spaces. */
export const ALIASES: Record<string, string> = {
  // Broken access control family
  idor: "missing_authz",
  bola: "missing_authz",
  "broken object level authorization": "missing_authz",
  "insecure direct object reference": "missing_authz",
  "broken access control": "missing_authz",
  authorization: "missing_authz",
  // CSRF family
  csrf: "missing_nonce",
  xsrf: "missing_nonce",
  "cross site request forgery": "missing_nonce",
  "cross-site request forgery": "missing_nonce",
  // Injection family
  sqli: "sql_injection",
  "sql injection": "sql_injection",
  "sql-injection": "sql_injection",
  ssti: "ssti",
  "template injection": "ssti",
  "server side template injection": "ssti",
  // Command injection / RCE family
  "command injection": "command_injection",
  "os command injection": "command_injection",
  "command execution": "command_injection",
  "cmd injection": "command_injection",
  rce: "command_injection",
  "remote code execution": "command_injection",
  "code execution": "command_injection",
  "code injection": "command_injection",
  "eval injection": "command_injection",
  "arbitrary code execution": "command_injection",
  xxe: "xxe",
  "xml external entity": "xxe",
  "xxe injection": "xxe",
  // Mass assignment family
  bpla: "mass_assignment",
  "broken property level authorization": "mass_assignment",
  "mass assignment": "mass_assignment",
  // Path traversal family
  lfi: "path_confusion",
  rfi: "path_confusion",
  "path traversal": "path_confusion",
  "directory traversal": "path_confusion",
  "local file inclusion": "path_confusion",
  "remote file inclusion": "path_confusion",
  // SSRF
  ssrf: "ssrf",
  "server side request forgery": "ssrf",
  "server-side request forgery": "ssrf",
  // Modern / next-gen
  "prompt injection": "llm_injection",
  llm: "llm_injection",
  llm01: "llm_injection",
  "llm prompt injection": "llm_injection",
  graphql: "graphql_exposure",
  oauth: "oauth_misconfig",
  "open redirect": "oauth_misconfig",
  grpc: "grpc_reflection",
  // Credential / secret
  "hardcoded credential": "hardcoded_secret",
  "hardcoded secret": "hardcoded_secret",
  "credential leak": "hardcoded_secret",
  "hard coded credentials": "hardcoded_secret",
  // Privilege escalation
  "priv esc": "priv_esc",
  privesc: "priv_esc",
  "privilege escalation": "priv_esc",
  // Upload
  "file upload": "file_upload",
  "unrestricted upload": "file_upload",
  "unrestricted file upload": "file_upload",
  // Deserialization
  deserialization: "deserialization",
  "insecure deserialization": "deserialization",
  unserialize: "deserialization",
  // Misc
  "type juggling": "type_juggling",
  "php type juggling": "type_juggling",
  "prototype pollution": "prototype_pollution",
  crlf: "crlf_injection",
  "header injection": "crlf_injection",
  "http response splitting": "crlf_injection",
  "wrong sanitizer": "wrong_sanitizer",
  "wrong context sanitization": "wrong_sanitizer",
  // Supply chain / ML (2026)
  "dependency confusion": "dependency_confusion",
  "dep confusion": "dependency_confusion",
  "supply chain": "dependency_confusion",
  "supply chain attack": "dependency_confusion",
  "ml supply chain": "ml_supply_chain",
  "ai supply chain": "ml_supply_chain",
  "model poisoning": "ml_supply_chain",
  "ml security": "ml_supply_chain",
  "ai ml security": "ml_supply_chain",
  // Rust
  "rust unsafe": "rust_unsafe",
  "unsafe rust": "rust_unsafe",
  "rust memory safety": "rust_unsafe",
  "transmute": "rust_unsafe",
  "rust format string": "rust_format_string",
  "format string": "rust_format_string",
  "format string injection": "rust_format_string",
  // JWT algorithm confusion + cache deception
  jwt: "jwt_alg_confusion",
  "jwt algorithm confusion": "jwt_alg_confusion",
  "jwt alg confusion": "jwt_alg_confusion",
  "alg confusion": "jwt_alg_confusion",
  "rs256 hs256": "jwt_alg_confusion",
  "web cache deception": "cache_deception",
  "cache deception": "cache_deception",
  "cache poisoning": "cache_deception",
  "cache key injection": "cache_deception",
  // CORS / XSS / subdomain takeover
  cors: "cors_misconfiguration",
  "cors misconfiguration": "cors_misconfiguration",
  "cors misconfig": "cors_misconfiguration",
  "cross origin resource sharing": "cors_misconfiguration",
  xss: "xss",
  "cross site scripting": "xss",
  "cross-site scripting": "xss",
  "dom xss": "xss",
  "reflected xss": "xss",
  "stored xss": "xss",
  "subdomain takeover": "subdomain_takeover",
  takeover: "subdomain_takeover",
  "dangling dns": "subdomain_takeover",
  "dangling cname": "subdomain_takeover",
};

/** Normalize a term to the key form: lowercase, collapse separators to spaces. */
export function normalize(term: string): string {
  return term.trim().toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
}

/** Resolve a free-form term to its canonical detector id. If no alias matches,
 *  return the term normalized to snake_case (so exact ids still pass through). */
export function canonicalId(term: string): string {
  const key = normalize(term);
  if (ALIASES[key]) return ALIASES[key];
  return key.replace(/ /g, "_");
}

/** Given a free-form query, return the canonical id + every alias that maps to it. */
export function synonymsFor(term: string): { canonical: string; aliases: string[] } {
  const canonical = canonicalId(term);
  const aliases = Object.entries(ALIASES)
    .filter(([, v]) => v === canonical)
    .map(([k]) => k);
  return { canonical, aliases };
}

/** List every alias→canonical mapping (for introspection / the MCP tool). */
export function listAliases(): Array<{ alias: string; canonical: string }> {
  return Object.entries(ALIASES).map(([alias, canonical]) => ({ alias, canonical }));
}
