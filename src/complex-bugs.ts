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
 */
const SOURCE_TOKENS = /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$request->|\$req->|request\.(get|input|query|post|data|body|headers|cookies|params)|getParameter\(|req\.(query|body|params|headers|cookies)/;

function lines(code: string): string[] {
  return code.split("\n");
}

function lineNo(code: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

export type ComplexBugType =
  | "deserialization"
  | "type_juggling"
  | "mass_assignment"
  | "prototype_pollution"
  | "crlf_injection"
  | "path_confusion";

export interface ComplexFinding {
  file: string;
  line: number;
  type: ComplexBugType;
  category: string;
  severity: "high" | "medium";
  evidence: string;
  detail: string;
}

const MAGIC_METHODS = /\b(__destruct|__wakeup|__toString|__invoke|__call|__get|__set|__isset|__unset|__sleep)\s*\(/;

function detectDeserialization(code: string, file: string, out: ComplexFinding[]): void {
  // The taint engine already flags `unserialize($user_input)`. This detector's
  // unique signal is the POP-gadget escalation: unserialize + a magic method
  // (`__destruct`/`__wakeup`/`__toString`/…) in the same file.
  if (!MAGIC_METHODS.test(code)) return;
  const ls = lines(code);
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
    const hasHash = /\b(md5|sha1|sha256|hash|crc32|crypt|password_verify|strcmp|hash_equals|secret|token|nonce)\s*\(?/i.test(l) || /\b(secret|token|nonce|hash)\b/i.test(l);
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
  const mergeRe = /\b(Object\.assign|_\.merge|_\.defaultsDeep|\.extend|\.merge|\.defaultsDeep|mergeDeep|deepMerge|_.set)\s*\(/g;
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
  const headerRe = /\b(header|setHeader|addHeader|writeHead|appendHeader)\s*\(/g;
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
