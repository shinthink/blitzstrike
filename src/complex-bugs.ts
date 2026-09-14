/** Complex-bug detection — patterns that go beyond source→sink taint.
 *
 * These are the "hard" vulnerability classes that dominate modern frameworks:
 *
 *   - deserialization   — `unserialize()`/`pickle.loads`/`readObject` of
 *                         attacker-controlled data, escalated by a magic
 *                         method (`__destruct`/`__wakeup`/`__toString`/…).
 *   - type_juggling     — loose comparison (`==`/`!=`) of user input against a
 *                         hash/secret (PHP `0e` hash collision auth bypass).
 *   - mass_assignment   — `extract()`/`parse_str()` of request data without a
 *                         safe flag (variable injection → LFI/RCE/auth bypass).
 *   - wrong_sanitizer   — a value sanitized for context X reaching a sink that
 *                         requires context Y (the security-state lattice).
 */
import { detectWrongSanitizer } from "./security-state.js";
import { detectMissingAuthz } from "./framework-security.js";
import { SECRET_FIELDS, SECRET_FORMATS, shannonEntropy } from "./secrets.js";

const SOURCE_TOKENS = /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request->|\$req->|request\.(get|input|query|post|data|body|headers|cookies|params|args|form|values|json)|getParameter\(|req\.(query|body|params|headers|cookies|args|form)|php:\/\/input/;

function lines(code: string): string[] {
  return code.split("\n");
}

function lineNo(code: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

/** Strip only COMMENTS (//, #, /* … *​/) — NOT string literals — preserving
 *  character positions and line numbers. A sink token inside a docblock is not
 *  a real call, but detectors that match string literals (e.g. uploadAllow
 *  => 'all') must still see them. */
function stripCommentsOnly(code: string): string {
  const out = code.split("");
  const n = code.length;
  let i = 0;
  while (i < n) {
    const c = code[i];
    const nc = code[i + 1];
    if (c === "'" || c === '"') {
      // keep string literals intact — skip to the closing quote
      const q = c;
      i++;
      while (i < n && code[i] !== q) {
        if (code[i] === "\\") i++;
        i++;
      }
      i++;
      continue;
    }
    if ((c === "/" && nc === "/") || c === "#") {
      while (i < n && code[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }
    if (c === "/" && nc === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < n && !(code[i] === "*" && code[i + 1] === "/")) {
        if (code[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) {
        out[i] = " ";
        if (i + 1 < n) out[i + 1] = " ";
        i += 2;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

export type ComplexBugType =
  | "deserialization"
  | "type_juggling"
  | "mass_assignment"
  | "prototype_pollution"
  | "crlf_injection"
  | "path_confusion"
  | "ssrf"
  | "xxe"
  | "ssti"
  | "wrong_sanitizer"
  | "missing_authz"
  | "missing_nonce"
  | "file_upload"
  | "sql_injection"
  | "priv_esc"
  | "hardcoded_secret"
  | "llm_injection"
  | "graphql_exposure"
  | "oauth_misconfig"
  | "grpc_reflection"
  | "dependency_confusion"
  | "ml_supply_chain"
  | "rust_unsafe"
  | "rust_format_string"
  | "jwt_alg_confusion"
  | "cache_deception"
  | "cors_misconfiguration"
  | "xss"
  | "subdomain_takeover";

export interface ComplexFinding {
  file: string;
  line: number;
  type: ComplexBugType;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  evidence: string;
  detail: string;
}

const MAGIC_METHODS = /\b(__destruct|__wakeup|__toString|__invoke|__call|__get|__set|__isset|__unset|__sleep)\s*\(/;

function detectDeserialization(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  // (1) PHP unserialize — the POP-gadget escalation signal requires a magic method
  // (`__destruct`/`__wakeup`/`__toString`/…) in the same file.
  if (MAGIC_METHODS.test(code)) {
    const re = /\b(unserialize|maybe_unserialize)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const ln = lineNo(code, m.index);
      const l = ls[ln - 1] ?? "";
      const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
      if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
      out.push({
        file,
        line: ln,
        type: "deserialization",
        category: "Deserialization → POP gadget chain",
        severity: "high",
        evidence: l.trim(),
        detail: `\`${m[1]}()\` of attacker-controlled data AND a magic method is present — object injection can pivot to RCE via the gadget chain.`,
      });
    }
  }
  // (2) Non-PHP unsafe deserialization — direct RCE, no gadget chain needed.
  const unsafeRe = /\b(pickle\.loads?|yaml\.load|yaml\.unsafe_load|ObjectInputStream|\.readObject)\s*\(/g;
  let u: RegExpExecArray | null;
  while ((u = unsafeRe.exec(code)) !== null) {
    const ln = lineNo(code, u.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "deserialization",
      category: "Unsafe deserialization",
      severity: "high",
      evidence: l.trim(),
      detail: `\`${u[1]}\` of attacker-controlled data — unsafe deserialization can execute arbitrary code directly (pickle/yaml/Java object streams).`,
    });
  }
}

function detectTypeJuggling(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  // Loose comparison (== / !=) — skip strict (=== / !==) and assignment (=).
  const re = /(?<![=!<>])(==|!=)(?!=)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    // Only meaningful when user input is compared against a hash/secret.
    const hasSource = SOURCE_TOKENS.test(l) || SOURCE_TOKENS.test(scope);
    const hasHash = /\b(md5|sha1|sha256|hash|crc32|crypt|password_verify|strcmp|hash_equals|secret|token|nonce)\s*\(?/i.test(l) || /(secret|token|nonce|hash)\b/i.test(l);
    if (!hasSource || !hasHash) continue;
    out.push({
      file,
      line: ln,
      type: "type_juggling",
      category: "Type juggling (loose comparison)",
      severity: "medium",
      evidence: l.trim(),
      detail: "Loose comparison of user input against a hash/secret — PHP type juggling (`0e…`, `\"str\" == 0`) may bypass the check. Use strict `===`.",
    });
  }
}

function detectMassAssignment(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  // extract() without EXTR_SKIP / EXTR_PREFIX_ALL.
  const extractRe = /\bextract\s*\(\s*[^)]*(REQUEST|POST|GET|COOKIE|FILES|\$_(REQUEST|POST|GET|COOKIE|FILES))/g;
  let m: RegExpExecArray | null;
  while ((m = extractRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    if (/EXTR_SKIP|EXTR_PREFIX_ALL/.test(l)) continue;
    out.push({
      file,
      line: ln,
      type: "mass_assignment",
      category: "Mass assignment (variable injection)",
      severity: "high",
      evidence: l.trim(),
      detail: "`extract()` of request data without EXTR_SKIP — attacker can overwrite arbitrary variables.",
    });
  }
  const parseRe = /\bparse_str\s*\(/g;
  while ((m = parseRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 3), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "mass_assignment",
      category: "Mass assignment (variable injection)",
      severity: "medium",
      evidence: l.trim(),
      detail: "`parse_str()` of user input into the symbol table — variable injection.",
    });
  }
  // Dynamic field binding — `foreach ($_POST as $k => $v) { $this->$k = $v; }`.
  const bindRe = /foreach\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b[^)]*\)\s*\{[^}]*\$this->\$[A-Za-z_]\w*\s*=/g;
  while ((m = bindRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    out.push({
      file,
      line: ln,
      type: "mass_assignment",
      category: "Mass assignment (dynamic field binding)",
      severity: "high",
      evidence: l.trim(),
      detail: "Request keys are bound to object properties without an allowlist — attacker can set privileged fields (role, is_admin).",
    });
  }
  // Framework mass-assign — `Model.create(req.body)` without an allowlist.
  const createRe = /\.create\s*\(\s*(req\.body|req\.query|request\.body|request\.data|\$_(POST|REQUEST))\b/g;
  while ((m = createRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    out.push({
      file,
      line: ln,
      type: "mass_assignment",
      category: "Mass assignment (unrestricted model create)",
      severity: "high",
      evidence: l.trim(),
      detail: "A model is created directly from request data without an allowlist — attacker can set privileged fields.",
    });
  }
}

/** Run all complex-bug detectors over one file's source. */
export function detectComplexBugs(code: string, file: string): ComplexFinding[] {
  const out: ComplexFinding[] = [];
  detectDeserialization(code, file, out);
  detectTypeJuggling(code, file, out);
  detectMassAssignment(code, file, out);
  detectPrototypePollution(code, file, out);
  detectCrlfInjection(code, file, out);
  detectPathConfusion(code, file, out);
  detectSsrF(code, file, out);
  detectXxe(code, file, out);
  detectSsti(code, file, out);
  detectFileUploadRce(code, file, out);
  detectUnrestrictedUpload(code, file, out);
  detectSqlInjection(code, file, out);
  detectHardcodedSecret(code, file, out);
  detectLlmInjection(code, file, out);
  detectGraphqlExposure(code, file, out);
  detectOauthMisconfig(code, file, out);
  detectGrpcReflection(code, file, out);
  detectDependencyConfusion(code, file, out);
  detectMlSupplyChain(code, file, out);
  detectRustUnsafe(code, file, out);
  detectRustFormatString(code, file, out);
  detectJwtAlgConfusion(code, file, out);
  detectCacheDeception(code, file, out);
  detectCorsMisconfig(code, file, out);
  detectXss(code, file, out);
  detectSubdomainTakeover(code, file, out);
  out.push(...detectWrongSanitizer(code, file));
  out.push(...detectMissingAuthz(code, file));
  // Dedup by (type, line): a loose-comparison `==` also appearing in a comment
  // or a sink token matched twice would otherwise surface as duplicates.
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.type}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Prototype pollution — unsafe merge/extend of request data (Node/JS).
// ---------------------------------------------------------------------------

function detectPrototypePollution(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  // Unsafe merge sinks: Object.assign / _.merge / $.extend / deep merge helpers.
  const mergeRe = /(Object\.assign|_\.merge|_\.defaultsDeep|\.extend|\.merge|\.defaultsDeep|mergeDeep|deepMerge|_\.set)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = mergeRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "prototype_pollution",
      category: "Prototype pollution (unsafe merge)",
      severity: "high",
      evidence: l.trim(),
      detail: "Merge/extend of request data into an object without a `__proto__`/`constructor.prototype` guard — attacker-controlled keys can pollute `Object.prototype` and pivot to RCE or property injection.",
    });
  }
}

// ---------------------------------------------------------------------------
// CRLF / header injection — user input into an HTTP header or Location.
// ---------------------------------------------------------------------------

function detectCrlfInjection(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const headerRe = /\b(header|setHeader|addHeader|writeHead|appendHeader|setcookie|setCookie|set_cookie)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = headerRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 3), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "crlf_injection",
      category: "CRLF / header injection",
      severity: "medium",
      evidence: l.trim(),
      detail: "User input reaches an HTTP header — CRLF (`%0d%0a`) can split the response, inject headers, or poison cookies. Strip newlines from header values.",
    });
  }
}

// ---------------------------------------------------------------------------
// Path confusion — user input into a file path without canonicalization.
// ---------------------------------------------------------------------------

function detectPathConfusion(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const fileRe = /\b(file_get_contents|file_put_contents|fopen|readFileSync|readFile|open|include|require|new\s+File|Files\.read|FileInputStream|FileOutputStream)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = fileRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 3), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    // A canonicalization/normalization call nearby is a (weak) defense — skip it.
    if (/\b(basename|realpath|canonicalPath|getCanonicalPath|normalize|resolve|toRealPath)\s*\(/i.test(scope + "\n" + l)) continue;
    // Whitelist lookup `$allowed[$p]` — the user var is an array index, not a raw path.
    if (/\$[A-Za-z_]\w*\s*\[\s*\$[A-Za-z_]\w*\s*\]/.test(scope + "\n" + l)) continue;
    // A URL literal ("https://…") means this is a URL fetch (SSRF's domain), not a
    // file path — path traversal doesn't apply to scheme:// URLs.
    if (/["'][^"']*:\/\/[^"']*["']/.test(scope + "\n" + l)) continue;
    out.push({
      file,
      line: ln,
      type: "path_confusion",
      category: "Path confusion (unsanitized file path)",
      severity: "medium",
      evidence: l.trim(),
      detail: "User input reaches a file path with no canonicalization (`basename`/`realpath`/`normalize`) — traversal, `..%2f`, backslash and null-byte variants can confuse a naive `../` filter.",
    });
  }
}

// ---------------------------------------------------------------------------
// SSRF — user-controlled URL reaches a URL-accepting sink with no host allowlist.
// ---------------------------------------------------------------------------
function detectSsrF(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const re = /\b(file_get_contents|fopen|file|readfile|curl_setopt|curl_init|fetch|axios\.(get|post|put|request|delete|head)|requests\.(get|post|put)|urllib\.request|http_get|wp_remote_(get|post)|new\s+URL\s*\(|got\(|http\.(get|request))\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 3), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    // A host allowlist / scheme check / basename() nearby is a (weak) defense — skip it.
    if (/(allowlist|whitelist|in_array|preg_match|parse_url|startsWith\(["']https?|endsWith\(["']|basename|realpath|normalize)/i.test(scope + "\n" + l)) continue;
    // A fixed scheme+host literal ("https://api.example.com/" + input) means the host
    // is NOT attacker-controlled (only the path/query is) — constrained, not SSRF.
    if (/["'][^"']*:\/\/[^"']*["']/.test(scope + "\n" + l)) continue;
    out.push({
      file,
      line: ln,
      type: "ssrf",
      category: "SSRF (user-controlled URL)",
      severity: "high",
      evidence: l.trim(),
      detail: "User input reaches a URL-accepting sink with no host allowlist — SSRF (cloud metadata, internal port scan, IAM credential theft).",
    });
  }
}

// ---------------------------------------------------------------------------
// XXE — user-controlled XML parsed without disabling external entities.
// ---------------------------------------------------------------------------
function detectXxe(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const re = /\b(simplexml_load_string|simplexml_load_file|new\s+SimpleXMLElement|->loadXML\s*\(|->load\s*\(|XMLReader\s*->\s*XML\s*\(|libxml_parse|DocumentBuilderFactory|SAXParserFactory|SAXReader)\s*\(?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 4), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    // libxml_disable_entity_loader(true) or LIBXML_NONET is the defense — skip it.
    if (/libxml_disable_entity_loader\s*\(\s*true|LIBXML_NONET/.test(scope + "\n" + l)) continue;
    out.push({
      file,
      line: ln,
      type: "xxe",
      category: "XXE (unprotected XML parse)",
      severity: "high",
      evidence: l.trim(),
      detail: "User-controlled XML parsed without disabling external entities — XXE (file read, SSRF, billion-laughs DoS).",
    });
  }
}

// ---------------------------------------------------------------------------
// SSTI — user input reaches a template render with no sandbox.
// ---------------------------------------------------------------------------
function detectSsti(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const re = /(render_template_string|Template\s*\(|res\.render\s*\(|ejs\.(render|compile)\s*\(|_\.template\s*\(|render_string|twig->render|createTemplate\s*\(|Jinja2\(|jinja2\.Template|jinja2\.from_string|jinja2\.Environment)\s*\(?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 3), ln).join("\n");
    if (!SOURCE_TOKENS.test(l) && !SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "ssti",
      category: "SSTI (template render of user input)",
      severity: "high",
      evidence: l.trim(),
      detail: "User input reaches a template render with no sandbox — SSTI (`{{7*7}}`, `${7*7}`, `#{7*7}`) → RCE.",
    });
  }

  // Liquid (Shopify/Python) — `from liquid import Template` + `Template(var)`
  // where the arg is a variable (stored profile/field), i.e. user input becomes
  // template source. The source is indirect (a stored field), so the direct
  // SOURCE_TOKENS check above misses it.
  if (/from\s+liquid\s+import\s+Template|liquid\.Template|import\s+liquid/.test(code)) {
    const tRe = /\bTemplate\s*\(\s*([a-z_][a-z0-9_]*)\s*\)/g;
    while ((m = tRe.exec(code)) !== null) {
      const ln = lineNo(code, m.index);
      out.push({
        file, line: ln, type: "ssti",
        category: "SSTI (Liquid template source from stored input)",
        severity: "high",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: "A Liquid template is compiled from a variable (`Template(var)`) with no template-syntax screening — profile/stored input becomes template source, so `{{ ... }}` tags execute server-side (SSTI → data exfiltration / RCE). Render with an explicit, static template and pass user values only as variables.",
      });
    }
  }
}

// ---------------------------------------------------------------------------
// File upload → RCE — an uploaded file is written with an attacker-controlled
// name/extension and no visible filetype/extension validation.
// ---------------------------------------------------------------------------
function detectFileUploadRce(code: string, file: string, out: ComplexFinding[]): void {
  code = stripCommentsOnly(code);
  const ls = lines(code);
  // Upload sinks that write the file to disk (not `file_put_contents`, which is
  // too generic — cache/logging use it constantly).
  const re = /\b(move_uploaded_file|wp_upload_bits|->move|storeAs|->storeAs|putFile|\.save|uploadFile)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    // Wide scope (whole function region): the extension whitelist / anti-script
    // sanitizer often lives 10-30 lines above the sink (e.g. an antiscript filename helper).
    const scope = ls.slice(Math.max(0, ln - 30), ln + 3).join("\n");
    // Must involve an uploaded file whose NAME is attacker-controlled.
    if (!/\$_FILES\b|tmp_name|getUploadedFile|uploadedFile|req\.files|\['name'\]|\.name/i.test(scope)) continue;
    // Defense: a filetype check or an extension whitelist/blacklist nearby.
    if (/(wp_check_filetype|PATHINFO_EXTENSION|wp_get_mime_types|allowed_?(types|extensions|exts)|mime_?(types|extensions)|in_array\s*\([^)]*\$(?:allowed|whitelist|ext)|wp_handle_upload\s*\(\s*[^)]*test_form\s*=>\s*true)/i.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "file_upload",
      category: "File upload → RCE (unvalidated extension)",
      severity: "high",
      evidence: l.trim(),
      detail: "An uploaded file is written with an attacker-controlled name and no visible extension/filetype validation — upload a .php/.phtml shell → RCE.",
    });
  }
}

// ---------------------------------------------------------------------------
// Unrestricted upload config — a file-manager/connector config sets uploadAllow
// to 'all' (or uploadOrder deny→allow with 'all'), so ANY mimetype — including
// .php/.phtml — can be uploaded. This is the classic file-manager connector
// misconfiguration: `'uploadAllow' => array('all'), 'uploadOrder' => array('deny','allow')`.
// ---------------------------------------------------------------------------
function detectUnrestrictedUpload(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const re = /['"]uploadAllow['"]\s*=>\s*(?:array\s*\(\s*)?['"]all['"]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    // Stronger signal: deny→allow order means the allow list overrides the deny list.
    const scope = ls.slice(Math.max(0, ln - 4), ln + 4).join("\n");
    const denyFirst = /['"]uploadOrder['"]\s*=>\s*array\s*\(\s*['"]deny['"]/.test(scope);
    out.push({
      file,
      line: ln,
      type: "file_upload",
      category: "Unrestricted upload config (uploadAllow=all)",
      severity: denyFirst ? "high" : "medium",
      evidence: l.trim(),
      detail: denyFirst
        ? "File-manager/connector config sets uploadAllow='all' with uploadOrder deny→allow — every mimetype (including .php) is uploadable → RCE."
        : "File-manager/connector config sets uploadAllow='all' — any file type can be uploaded; verify the upload path is not web-reachable or that a server-side extension whitelist exists.",
    });
  }
}

// ---------------------------------------------------------------------------
// SQL injection — a SQL sink receives a query built by string concatenation
// (not prepared). This targets the CROSS-FILE case: the taint engine already
// catches same-file source→sink SQLi, so here we only flag when NO request
// source is visible in scope (the concatenated variable comes from another
// file / a caller) — a lead to trace back to a source.
// ---------------------------------------------------------------------------
function detectSqlInjection(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const sinkRe = /\$wpdb->(get_results|get_col|get_var|get_row|query)\s*\(|[->.]query\s*\(|[->.]execute\s*\(|mysqli_query\s*\(|pg_query\s*\(|DB::unprepared\s*\(|[->.]whereRaw\s*\(|[->.]selectRaw\s*\(|sqlx::query(?:_as)?\s*\(\s*&\s*format!|sequelize\.query\s*\(|knex\.raw\s*\(|\bpool\.query\s*\(|\bclient\.query\s*\(|\bconnection\.query\s*\(|\bdb\.query\s*\(|\bpg\.query\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = sinkRe.exec(code)) !== null) {
    const ln = lineNo(code, m.index);
    const l = ls[ln - 1] ?? "";
    const scope = ls.slice(Math.max(0, ln - 6), ln + 1).join("\n");
    // Prepared statements are safe.
    if (/->prepare\s*\(/.test(scope)) continue;
    // The taint engine handles same-file sources; here we target the case where
    // the source lives elsewhere — so skip if a source token is in scope.
    if (SOURCE_TOKENS.test(scope)) continue;
    // String-interpolation signals:
    //   PHP  : `. $var` on the sink line, or `$q = "..." . $var` / `$q .= ...`
    //   Node : `${var}` template-literal interpolation, or `'...' + var` concat
    //   Python: f-string `f"...{var}..."` interpolation
    const inlineConcat = /(\.\s*\$[A-Za-z_]\w*|\+\s*[A-Za-z_$]\w*|\$\{[^}]+\}|<<\s*[A-Za-z_$]|\{[A-Za-z_]\w*\})/.test(l);
    const assignConcat = /(?:^|\n)\s*\$[A-Za-z_]\w*\s*(?:\.=|=)\s*[^;\n]*["'][^"']*["']\s*\.\s*\$[A-Za-z_]\w*/.test(scope)
      || /(?:^|\n)\s*(?:const|let|var)\s+[A-Za-z_$]\w*\s*=\s*`[^`]*\$\{[^}]+\}[^`]*`/.test(scope)
      || /(?:^|\n)\s*[A-Za-z_]\w*\s*=\s*f["']/.test(scope);
    if (!inlineConcat && !assignConcat) continue;
    out.push({
      file,
      line: ln,
      type: "sql_injection",
      category: "SQL injection (raw string-interpolated query)",
      severity: "medium",
      evidence: l.trim(),
      detail: "A SQL sink receives a query built by string concatenation (not prepared), with no visible source in this file — trace the concatenated variable back to a request source; if user-controlled, this is SQL injection (CWE-89).",
    });
  }
}

// ---------------------------------------------------------------------------
// Hardcoded secret (CWE-798) — three tiers, by precision → recall:
//   1. FIELD NAME — a known secret field (api_key, db_password, …) assigned a
//      literal. HIGH confidence.
//   2. FORMAT — a known secret format (JWT/AWS/GitHub/…) regardless of the name.
//      HIGH confidence.
//   3. ENTROPY — a high-entropy token (Shannon ≥ 4 bits/char) under a non-obvious
//      variable name. MEDIUM (suspect — verify). Field names + formats live in
//      secrets.ts (single source of truth).
// ---------------------------------------------------------------------------
const SECRET_FIELD_RE = new RegExp(`\\b(${SECRET_FIELDS})\\s*(?:::|=>|=|:)\\s*`, "gi");

const SECRET_PLACEHOLDER_RE = /^(null|true|false|undefined|your_|xxx+|changeme|example|placeholder|test|secret|password|token|key|api|smtp|localhost|root|admin|pass|change|me|none|na|foo|bar|dummy)$/i;

/** Variable names that legitimately hold high-entropy non-secret values. */
const ENTROPY_EXCLUDE_VAR = /\b(data|payload|content|body|base64|encoded|encode|image|binary|blob|hash|digest|checksum|nonce|uuid|etag|signature|sig|cipher|iv|ciphertext|plaintext|thumb|thumbnail)\b/i;

function detectHardcodedSecret(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const flaggedLines = new Set<number>();

  // Tier 1 — secret field name assigned a literal value.
  SECRET_FIELD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SECRET_FIELD_RE.exec(clean)) !== null) {
    const field = m[1];
    const rest = clean.slice(m.index + m[0].length);
    const lineEnd = rest.search(/\r?\n/);
    const valueRaw = (lineEnd === -1 ? rest : rest.slice(0, lineEnd)).trim();
    // Extract a literal value: a quoted string, or a bare token up to a delimiter.
    let value = "";
    const qm = valueRaw.match(/^["']([^"']{4,})["']/);
    if (qm) value = qm[1];
    else value = (valueRaw.match(/^([A-Za-z0-9._/+=@-]{8,})/) ?? [])[1] ?? "";
    if (!value) continue;
    // Not a hardcoded literal: placeholder, environment lookup, or a variable.
    if (SECRET_PLACEHOLDER_RE.test(value)) continue;
    if (/\$[A-Za-z_]|[{}\[\]]|process\.env|getenv|os\.environ|config\s*\(|env\s*\(/.test(valueRaw)) continue;
    // Suppress CTF/benchmark flag markers: a `FLAG{nusasec-...}` literal or a
    // bare `FLAG` env reference is the challenge's seeded answer, NOT a real
    // hardcoded credential (CWE-798 does not apply to a deliberately-seeded flag).
    if (/^FLAG\{[a-z0-9_\-]+\}$/i.test(value) || /^FLAG$/i.test(value)) continue;
    // A quoted prefix followed by concatenation (e.g. `'usr_' + randomBytes(8)`)
    // is not a complete hardcoded secret — the real value is built at runtime.
    if (qm && /^["'][^"']+["']\s*\+/.test(valueRaw)) continue;
    // A bare token that is actually a FUNCTION CALL (getApiKeyFromRequest(...)),
    // a DOM read (document.getElementById(...).value), or an object access — the
    // value is computed at runtime, not a hardcoded literal.
    if (!qm && new RegExp(`${value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\(`).test(valueRaw)) continue;
    if (!qm && /document\.|window\.|localStorage\.|sessionStorage\./.test(valueRaw)) continue;
    const ln = lineNo(code, m.index);
    flaggedLines.add(ln);
    // Escalate: if the literal also matches a known secret FORMAT, take that
    // format's more precise severity + category (e.g. a sk_live_ value under a
    // SECRET_KEY field is CRITICAL, not just "high").
    let sev: ComplexFinding["severity"] = "high";
    let cat = "Hardcoded secret (credential in source)";
    let detail = `Secret field '${field}' is assigned a hardcoded value in source — the credential is exposed to anyone with code access (CWE-798 Hard-coded Credentials). Rotate it and load from the environment instead.`;
    for (const fmt of SECRET_FORMATS) {
      fmt.re.lastIndex = 0;
      if (fmt.re.test(value)) {
        sev = fmt.severity;
        cat = `Hardcoded secret (${fmt.category}: ${fmt.name})`;
        detail = `${fmt.name} was found hardcoded in source — the credential is exposed to anyone with code access (CWE-798, severity ${fmt.severity}). Rotate it and load from the environment instead.`;
        break;
      }
    }
    out.push({
      file,
      line: ln,
      type: "hardcoded_secret",
      category: cat,
      severity: sev,
      evidence: (ls[ln - 1] ?? "").trim(),
      detail,
    });
  }

  // Tier 2 — known secret FORMAT, regardless of variable name. Severity +
  // category come from the format definition (single source of truth).
  for (const fmt of SECRET_FORMATS) {
    fmt.re.lastIndex = 0;
    let fm: RegExpExecArray | null;
    while ((fm = fmt.re.exec(clean)) !== null) {
      const ln = lineNo(code, fm.index);
      if (flaggedLines.has(ln)) continue;
      flaggedLines.add(ln);
      out.push({
        file,
        line: ln,
        type: "hardcoded_secret",
        category: `Hardcoded secret (${fmt.category}: ${fmt.name})`,
        severity: fmt.severity,
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `${fmt.name} was found hardcoded in source — the credential is exposed to anyone with code access (CWE-798, severity ${fmt.severity}). Rotate it and load from the environment instead.`,
      });
    }
  }

  // Tier 3 — high-entropy token in an assignment context (suspect secret).
  // Conservative on purpose: a token-like base64url string, length ≥ 32, mixed
  // case + digit, Shannon ≥ 4.5 — excludes hashes, base64 blobs, and minified
  // bundles (where entropy is everywhere and means nothing).
  const isMinified = /\.min\.(js|css)$/i.test(file) || /[\\/](bundle|vendor|dist|build)[\\/]/i.test(file);
  if (!isMinified) {
    const entropyRe = /(\b[A-Za-z_]\w*)\s*(?:::|=>|=|:)\s*["']([A-Za-z0-9_-]{32,})["']/g;
    entropyRe.lastIndex = 0;
    let em: RegExpExecArray | null;
    while ((em = entropyRe.exec(clean)) !== null) {
      const varName = em[1];
      const value = em[2];
      const ln = lineNo(code, em.index);
      if (flaggedLines.has(ln)) continue;
      if (ENTROPY_EXCLUDE_VAR.test(varName)) continue;
      if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/[0-9]/.test(value)) continue; // mixed case + digit
      if (shannonEntropy(value) < 4.5) continue;
      flaggedLines.add(ln);
      out.push({
        file,
        line: ln,
        type: "hardcoded_secret",
        category: "Suspected secret (high-entropy token)",
        severity: "medium",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `'${varName}' is assigned a high-entropy token (Shannon ${shannonEntropy(value).toFixed(2)} bits/char) that looks like a generated credential — verify it is not a secret key/token (CWE-798).`,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Modern attack surface (2026): LLM prompt injection, GraphQL exposure, OAuth
// misconfiguration, gRPC reflection — the "next-gen" classes beyond classic web.
// ---------------------------------------------------------------------------

function detectLlmInjection(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const llmCallRe = /\b(?:openai|anthropic|langchain|llama_index)\.[A-Za-z_.]+\s*\(|\b(?:ChatCompletion|completion|messages)\.create\s*\(|\bllm\.invoke\s*\(|\.chat\.completions\.create\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = llmCallRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const scope = ls.slice(Math.max(0, ln - 6), ln + 3).join("\n");
    // Prompt-injection surface: request input reaches the LLM call with no
    // visible system-prompt boundary / output filtering.
    if (!SOURCE_TOKENS.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "llm_injection",
      category: "LLM prompt injection surface",
      severity: "medium",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: "Request input reaches an LLM call (chat/completion/invoke) with no visible prompt-injection boundary — untrusted text may override instructions or exfiltrate context (OWASP LLM01 Prompt Injection). Verify the prompt is sandboxed and output is not used for privileged actions.",
    });
  }
}

function detectGraphqlExposure(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const re = /\b(introspection|playground|graphiql)\s*[:=]\s*(true|1)\b/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    out.push({
      file,
      line: ln,
      type: "graphql_exposure",
      category: "GraphQL introspection/playground exposed",
      severity: "medium",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: `GraphQL ${m[1].toLowerCase()} is enabled (${m[2]}) in a configuration that appears production-reachable — introspection exposes the full schema/fields, and a playground enables interactive querying (CWE-200 Information Exposure). Disable in production.`,
    });
  }
}

function detectOauthMisconfig(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const re = /\b(redirect_uri|redirectUrl|return_url|returnUrl|callback_url)\s*[:=]\s*/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const rest = clean.slice(m.index + m[0].length);
    const lineEnd = rest.search(/\r?\n/);
    const line = lineEnd === -1 ? rest : rest.slice(0, lineEnd);
    // Only flag when the redirect target is attacker-controlled (request input).
    if (!/(request|params|query|\$_(?:GET|POST|REQUEST)|req\.)/i.test(line)) continue;
    // And no allowlist validation nearby.
    const scope = ls.slice(Math.max(0, ln - 6), ln + 3).join("\n");
    if (/(allowlist|whitelist|allowed_|in_array|startsWith|===\s*['"])/.test(scope)) continue;
    out.push({
      file,
      line: ln,
      type: "oauth_misconfig",
      category: "OAuth redirect_uri misconfiguration",
      severity: "high",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: "An OAuth redirect_uri/callback is fed by request input with no allowlist validation — an attacker can redirect the authorization code/token to an attacker-controlled endpoint (CWE-601 Open Redirect → token theft). Validate the redirect target against a static allowlist.",
    });
  }
}

function detectGrpcReflection(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const re = /grpc_reflection|enable_server_reflection|RegisterReflectionService|reflection\.enable|ServerReflection|ReflectionServicer|reflection\.Register/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    out.push({
      file,
      line: ln,
      type: "grpc_reflection",
      category: "gRPC reflection exposed",
      severity: "low",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: "gRPC server reflection is enabled — it enumerates every service/method to any caller, expanding the attack surface and leaking the API contract (CWE-200 Information Exposure). Disable reflection in production.",
    });
  }
}

// ---------------------------------------------------------------------------
// Dependency confusion (CWE-427) — a package resolves from a PUBLIC registry
// where an internal package name can be squatted by an attacker, pulling
// attacker-controlled code into the build. Two deterministic signals:
//   (1) a public index (PyPI/npm/rubygems) is the resolution source, and
//   (2) a scoped/internal package is referenced with no private registry pinned.
// ---------------------------------------------------------------------------
function detectDependencyConfusion(code: string, file: string, out: ComplexFinding[]): void {
  const isManifest = /package\.json|requirements|pipfile|gemfile|go\.mod|pom\.xml|setup\.py|pyproject|\.npmrc|pip\.conf|dockerfile|\.ya?ml$/i.test(file);
  if (!isManifest) return;
  const ls = lines(code);

  // Signal 1 — public registry as the (extra-)index / registry resolution source.
  const idxRe = /--(?:extra-)?index-url\s+["']?(https?:\/\/[^"'<\s]+)["']?/gi;
  let m: RegExpExecArray | null;
  while ((m = idxRe.exec(code)) !== null) {
    if (/pypi\.org|pythonhosted|npmjs\.org|rubygems\.org|golang\.org|crates\.io|maven\.apache\.org/i.test(m[1])) {
      const ln = lineNo(code, m.index);
      out.push({
        file, line: ln, type: "dependency_confusion",
        category: "Dependency confusion — public registry in resolution path",
        severity: "high",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `A public registry (${m[1]}) is the resolution source — an internal package name that exists or can be squatted on the public registry resolves there instead of the private one, pulling attacker-controlled code (CWE-427). Pin a private registry and namespace internal packages uniquely.`,
      });
    }
  }

  // Signal 2 — scoped/internal package referenced with NO private registry pinned.
  const hasPrivateRegistry = /--(?:index-url|registry)\s+["']?(?!https?:\/\/pypi\.org|https?:\/\/registry\.npmjs\.org)/i.test(code)
    || /(?:registry|index[-_]url)\s*[:=]\s*["']https?:\/\/(?!.*(?:pypi\.org|registry\.npmjs\.org))/i.test(code);
  if (!hasPrivateRegistry) {
    const scopedRe = /["'](@[a-z0-9][a-z0-9-]*\/[a-z0-9_.-]+)["']/g;
    while ((m = scopedRe.exec(code)) !== null) {
      const ln = lineNo(code, m.index);
      out.push({
        file, line: ln, type: "dependency_confusion",
        category: "Dependency confusion — scoped package, no private registry",
        severity: "medium",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `The scoped package ${m[1]} is referenced but no private registry is pinned — if the @scope is not registered/reserved on the public registry, an attacker can publish ${m[1]} there and the build will pull malicious code (CWE-427). Verify the registry resolution and pin it.`,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// ML supply chain (CWE-502) — untrusted AI/ML model loading. Frameworks load
// models via pickle (RCE); loading a model from a URL / upload / user path
// without the safe flag is arbitrary code execution. Complementary to the
// deserialization detector: torch/joblib/keras/numpy are NOT covered there.
// ---------------------------------------------------------------------------
function detectMlSupplyChain(code: string, file: string, out: ComplexFinding[]): void {
  const ls = lines(code);
  const clean = stripCommentsOnly(code);

  interface MlSink { re: RegExp; name: string; note: string; skipIfSafe?: RegExp; requireFlag?: RegExp; }
  const sinks: MlSink[] = [
    { re: /torch\.load\s*\(/g, name: "torch.load", note: "uses pickle; pass weights_only=True", skipIfSafe: /weights_only\s*=\s*True/ },
    { re: /\bjoblib\.load\s*\(/g, name: "joblib.load", note: "uses pickle (no safe flag)" },
    { re: /(?:tf\.)?keras\.models\.load_model\s*\(/g, name: "keras load_model", note: "deserializes the model graph (pickle/h5)" },
    { re: /\bnp\.load\s*\(/g, name: "np.load", note: "allow_pickle=True is RCE", requireFlag: /allow_pickle\s*=\s*True/i },
  ];

  for (const s of sinks) {
    s.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = s.re.exec(clean)) !== null) {
      const ln = lineNo(code, m.index);
      const l = ls[ln - 1] ?? "";
      // torch: skip if weights_only=True is set on the call line.
      if (s.skipIfSafe && s.skipIfSafe.test(l)) continue;
      // np.load: only flag when allow_pickle=True is present.
      if (s.requireFlag && !s.requireFlag.test(l)) continue;
      // Source gate: np.load(allow_pickle=True) is dangerous regardless of source
      // (the flag IS the signal); the other sinks need a source hint
      // (URL / download / request / upload / user) to avoid FP on local models.
      const flagIsSignal = s.requireFlag != null;
      if (!flagIsSignal && !SOURCE_TOKENS.test(l) && !/https?:\/\//.test(l) && !/download|request|upload|user|input|temp|tmp/i.test(l)) continue;
      out.push({
        file, line: ln, type: "ml_supply_chain",
        category: "ML supply chain — untrusted model load",
        severity: "high",
        evidence: l.trim(),
        detail: `\`${s.name}\` loads a model from an untrusted source — ${s.note}. A poisoned model file executes arbitrary code on load (CWE-502). Pin hashes, load from a trusted artifact store, and use the safe flag where available.`,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Rust unsafe / memory-unsafety surface (CWE-119/787/416) — Rust's borrow
// checker guarantees memory safety only OUTSIDE `unsafe`; the dangerous
// constructs that bypass it are the signal, not the `unsafe` keyword itself
// (which is ubiquitous in FFI).
// ---------------------------------------------------------------------------
function detectRustUnsafe(code: string, file: string, out: ComplexFinding[]): void {
  if (!/\.rs$/i.test(file)) return;
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const re = /std::mem::transmute|\btransmute\s*\(|\bassume_init\s*\(|from_raw_parts(?:_mut)?\s*\(|ptr::(copy|copy_nonoverlapping|read|write|swap)\s*\(|from_utf8_unchecked\s*\(|\bunreachable_unchecked\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    out.push({
      file, line: ln, type: "rust_unsafe",
      category: "Rust unsafe / memory-unsafety surface",
      severity: "medium",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: `\`${m[0]}\` bypasses the borrow checker's memory-safety guarantees — type confusion (transmute), uninitialized reads (assume_init), or unchecked pointer/slice construction (from_raw_parts / ptr::*) can lead to out-of-bounds access, use-after-free, or UB (CWE-119/787/416). Verify the input is bounds-checked and no attacker-controlled length/index reaches it.`,
    });
  }
}

// ---------------------------------------------------------------------------
// Rust format string (CWE-134) — the FORMAT string itself is a variable rather
// than a literal, e.g. `println!(user_input)` instead of `println!("{}", user)`.
// Attacker-controlled format strings can read/write memory via positional args
// and width specifiers (Rust's format! is checked at compile time ONLY when the
// format string is a literal).
// ---------------------------------------------------------------------------
function detectRustFormatString(code: string, file: string, out: ComplexFinding[]): void {
  if (!/\.rs$/i.test(file)) return;
  const ls = lines(code);
  const clean = stripCommentsOnly(code);
  const re = /\b(format!|println!|print!|eprintln!|eprint!)\s*\(\s*([a-z_][a-z0-9_]*)\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    out.push({
      file, line: ln, type: "rust_format_string",
      category: "Rust format string injection",
      severity: "high",
      evidence: (ls[ln - 1] ?? "").trim(),
      detail: `\`${m[1]}\` passes a variable (\`${m[2]}\`) as the FORMAT string instead of a literal — if attacker-controlled, format specifiers (positional args, width, precision) can read or corrupt memory (CWE-134). Use \`${m[1]}!("{}", value)\` with the input as an argument, never as the format string.`,
    });
  }
}

// ---------------------------------------------------------------------------
// JWT algorithm confusion — a verifier that accepts BOTH RS256 (asymmetric) and
// HS256 (symmetric HMAC), where the HMAC secret is a PUBLIC/shared key. The
// attacker sets alg=HS256 and signs with the public key -> forge (CVE-2015-9235).
// ---------------------------------------------------------------------------
function detectJwtAlgConfusion(code: string, file: string, out: ComplexFinding[]): void {
  const clean = stripCommentsOnly(code);
  const hasRs256 = /\bRS256\b/.test(clean);
  const hasHs256 = /\bHS256\b/.test(clean);
  if (!hasRs256 || !hasHs256) return;
  // The dangerous shape: the HS256 path derives its HMAC secret from public key
  // material (or any shared/non-secret key), so anyone holding the public key can
  // sign. Also catches python-jwt / pyjwt decode(... algorithms=['HS256']).
  const hmacPublicKey =
    /createHmac\s*\(\s*['"]sha256['"]\s*,\s*(?:[A-Za-z_][\w.]*\.(?:publicKey|public_key|PUBLIC_KEY|verifying_key|verifyingKey)|publicKey|public_key|PUBLIC_KEY)/.test(clean)
    || /algorithms\s*=\s*\[[^\]]*['"]HS256['"]\s*,\s*['"]RS256['"]/.test(clean)
    || /algorithms\s*=\s*\[[^\]]*['"]RS256['"]\s*,\s*['"]HS256['"]/.test(clean);
  if (!hmacPublicKey) return;
  const ls = lines(code);
  const ln = lineNo(code, clean.search(/\bHS256\b/));
  out.push({
    file, line: ln, type: "jwt_alg_confusion",
    category: "JWT algorithm confusion (RS256 -> HS256)",
    severity: "critical",
    evidence: (ls[ln - 1] ?? "").trim(),
    detail: "The JWT verifier dispatches on the token's alg header and accepts BOTH RS256 and HS256, with the HS256 HMAC secret derived from public/shared key material. An attacker sets alg=HS256 and signs with the public key to forge a valid token (CVE-2015-9235 family). Pin the algorithm server-side (allow only RS256) and never reuse asymmetric public keys as symmetric HMAC secrets.",
  });
}

// ---------------------------------------------------------------------------
// Web cache deception — a reverse-proxy that caches static-extension URLs with a
// cache key that omits the session cookie, while the backend serves a greedy
// authenticated route. Cached private responses become world-readable.
// ---------------------------------------------------------------------------
function detectCacheDeception(code: string, file: string, out: ComplexFinding[]): void {
  const clean = stripCommentsOnly(code);
  // nginx (or similar) cache config: static-ext caching + cache key WITHOUT cookie.
  const staticCache = /proxy_cache\b|proxy_cache_path\b|proxy_cache_key\b/.test(clean);
  if (!staticCache) return;
  const cacheKeyNoCookie =
    /proxy_cache_key\s+[^;]*\$scheme[^;]*\$request_uri[^;]*;/.test(clean)
    && !/proxy_cache_key\s+[^;]*\$cookie/.test(clean);
  const staticExt = /location\s+~?\*?\s+\\?\.[a-z|()]*(css|js|png|jpg|jpeg|gif|ico|woff|svg|map)/.test(clean) || /location\s+~[*\s]*\\\./.test(clean);
  if (!cacheKeyNoCookie || !staticExt) return;
  const ls = lines(code);
  const ln = lineNo(code, clean.search(/proxy_cache_key\b/));
  out.push({
    file, line: ln, type: "cache_deception",
    category: "Web cache deception (cookie-less static cache key)",
    severity: "high",
    evidence: (ls[ln - 1] ?? "").trim(),
    detail: "The reverse proxy caches static-extension URLs using a cache key that excludes the session cookie, while a backend route (often a greedy regex like /account(/.*)?) returns per-session private data for such URLs. An attacker can poison the cache with a victim's session response and re-fetch it anonymously. Include the cookie in the cache key, or don't cache cookie-authenticated responses.",
  });
}

// ---------------------------------------------------------------------------
// CORS misconfiguration — Access-Control-Allow-Origin reflects the request
// Origin (or is '*') while credentials are allowed. An attacker page reads the
// victim's authenticated responses cross-origin.
// ---------------------------------------------------------------------------
function detectCorsMisconfig(code: string, file: string, out: ComplexFinding[]): void {
  const clean = stripCommentsOnly(code);
  const ls = lines(code);
  const hasCredentials =
    /Access-Control-Allow-Credentials['"]?\s*(?::|,|=)\s*['"]?true/i.test(clean)
    || /\ballow_credentials\s*=\s*True\b/i.test(clean)
    || /\bcredentials\s*:\s*true\b/i.test(clean)
    || /\bwithCredentials\s*:\s*true\b/i.test(clean);
  // ACAO reflects the request Origin (dynamic) or is '*' — the dangerous shape.
  const reflected =
    /Access-Control-Allow-Origin['"]?\s*(?::|,|=)\s*['"]?\*['"]?/i.test(clean)
    || /Access-Control-Allow-Origin['"]?\s*(?::|,|=)\s*[^,;\n]*\borigin\b/i.test(clean)
    || /allow_origins?\s*=\s*\[\s*['"]\*['"]\s*\]/i.test(clean)
    || /@CrossOrigin\s*\(\s*origins\s*=\s*['"]\*['"]/i.test(clean);
  if (!hasCredentials || !reflected) return;
  const ln = lineNo(code, clean.search(/Access-Control-Allow-Origin|allow_origins|@CrossOrigin|CORS\s*\(/i));
  out.push({
    file, line: ln, type: "cors_misconfiguration",
    category: "CORS misconfiguration (reflected origin + credentials)",
    severity: "high",
    evidence: (ls[ln - 1] ?? "").trim(),
    detail: "Access-Control-Allow-Origin reflects the request Origin (or is '*') while Access-Control-Allow-Credentials is true — any website can read the victim's authenticated responses cross-origin (CWE-942). Validate the Origin against a static allowlist and never combine a reflected/wildcard origin with credentials.",
  });
}

// ---------------------------------------------------------------------------
// XSS — user-controlled input reaching a DOM sink. The taint engine catches the
// direct source→sink path; this detector catches the framework shapes it misses
// (dangerouslySetInnerHTML, jQuery .html(), document.write, innerHTML/outerHTML,
// eval, insertAdjacentHTML) but only when the sink's ARGUMENT is a variable that
// actually flows from a user-controlled source (local taint flow), not merely
// when a source exists somewhere in the same file.
// ---------------------------------------------------------------------------
function detectXss(code: string, file: string, out: ComplexFinding[]): void {
  const clean = stripCommentsOnly(code);
  const ls = lines(code);

  // A user-controlled source expression (request params / location / URL parts / DOM reads).
  const isSourceExpr = (expr: string): boolean =>
    /\b(?:req\.(?:query|params|body|cookies|headers)|request\.(?:get|args|form|json|values|headers|params)|location\.(?:hash|search|href)|window\.location|document\.(?:URL|referrer)|URLSearchParams|searchParams\.get|getElementById\([^)]*\)\.value|routeParams|queryParams|this\.props)\b/i.test(expr);

  // Build the tainted-variable set via assignment flow (transitive, ≤3 hops):
  //   const u = location.hash;  →  u tainted
  //   const v = u;              →  v tainted
  const tainted = new Set<string>();
  const assignments: Array<{ lhs: string; rhs: string }> = [];
  const assignRe = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)/g;
  let m: RegExpExecArray | null;
  while ((m = assignRe.exec(clean)) !== null) {
    const lhs = m[1] ?? m[3];
    const rhs = (m[2] ?? m[4] ?? "").trim();
    if (lhs) assignments.push({ lhs, rhs });
  }
  for (let hop = 0; hop < 3; hop++) {
    let changed = false;
    for (const a of assignments) {
      if (tainted.has(a.lhs)) continue;
      const refsTainted = [...tainted].some((t) => new RegExp(`\\b${t}\\b`).test(a.rhs));
      if (isSourceExpr(a.rhs) || refsTainted) {
        tainted.add(a.lhs);
        changed = true;
      }
    }
    if (!changed) break;
  }
  if (tainted.size === 0) return;

  const sinkRe = /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|\.html\s*\(|eval\s*\(/g;
  const seen = new Set<number>();
  while ((m = sinkRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    if (seen.has(ln)) continue;
    const line = ls[ln - 1] ?? "";
    const rest = line.slice(line.indexOf(m[0]) + m[0].length);
    // skip constant-string sinks: innerHTML = "<b>x</b>", .html("static"), document.write("x")
    if (/^\s*["'`]/.test(rest)) continue;
    // the sink argument must reference a tainted variable (or be a direct source)
    const refsTainted = [...tainted].some((t) => new RegExp(`\\b${t}\\b`).test(rest));
    if (!refsTainted && !isSourceExpr(rest)) continue;
    seen.add(ln);
    out.push({
      file, line: ln, type: "xss",
      category: "Cross-site scripting (user input into a DOM sink)",
      severity: "high",
      evidence: line.trim(),
      detail: "User-controlled input reaches a DOM/JS sink (innerHTML / dangerouslySetInnerHTML / document.write / .html() / eval / insertAdjacentHTML). If the value is not sanitized or context-encoded, an attacker injects script that runs in a victim's session (CWE-79). Use textContent/value assignment, a DOM-purify allowlist, or a framework's escaping — never assign raw user data to an HTML sink.",
    });
  }
}

// ---------------------------------------------------------------------------
// Subdomain takeover — a DNS CNAME/AliasTarget/DNSName record points at a
// service that can be claimed by an attacker (GitHub Pages, S3, Heroku, …).
// ---------------------------------------------------------------------------
function detectSubdomainTakeover(code: string, file: string, out: ComplexFinding[]): void {
  const clean = stripCommentsOnly(code);
  const ls = lines(code);
  // Takeover-able service fingerprints (a CNAME target ending in these).
  const fingerprint = /(?:\.github\.io|\.s3[.-]?[a-z0-9-]*\.amazonaws\.com|\.herokuapp\.com|\.azurewebsites\.net|\.cloudfront\.net|\.fastly\.net|\.myshopify\.com|\.zendesk\.com|\.uservoice\.com|\.bitbucket\.io|\.readme\.io|\.ghost\.io|\.surge\.sh|\.netlify\.app|\.vercel\.app|\.firebaseapp\.com|\.elasticbeanstalk\.com|\.pantheon\.io|\.wordpress\.com|\.tumblr\.com|\.helpscoutdocs\.com|\.cargo\.site|\.getresponse\.com|\.teamwork\.com)\b/i;
  const targetRe = /["']([a-z0-9.-]+\.[a-z]{2,})["']/g;
  const seen = new Set<number>();
  // Find a DNS-record context line, then check its target on the same line.
  const ls2 = lines(clean);
  for (let i = 0; i < ls2.length; i++) {
    const line = ls2[i];
    if (!/(?:CNAME|AliasTarget|DNSName|aws_route53_record|dns_zone|records?\s*[:=]\s*\[)/i.test(line)) continue;
    let t: RegExpExecArray | null;
    while ((t = targetRe.exec(line)) !== null) {
      const target = t[1];
      if (!fingerprint.test(target)) continue;
      const ln = i + 1;
      if (seen.has(ln)) continue;
      seen.add(ln);
      out.push({
        file, line: ln, type: "subdomain_takeover",
        category: "Subdomain takeover (CNAME to a claimable service)",
        severity: "high",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `A DNS record points \`${target}\` at a service that can be claimed by an attacker (GitHub Pages/S3/Heroku/…). If the target is unclaimed/removed, an attacker registers it and hosts content on the victim's subdomain (cookie theft, phishing, same-origin attack). Verify the target resolves to a 'not found'/unclaimed service, then remove the dangling record.`,
      });
    }
  }
}
