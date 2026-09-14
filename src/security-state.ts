/** Security-State Lattice — the step beyond binary taint.
 *
 *  Binary taint only answers "tainted or not". Real complex bugs (the class a
 *  tool like Wordfence Argus finds) are CONTEXT bugs: the input WAS sanitized,
 *  but for the wrong sink — `sanitize_text_field()` (HTML) fed to a SQL query,
 *  or `esc_html()` fed to `eval()`.
 *
 *  This module models each value's SECURITY STATE as it flows:
 *
 *      clean < whitelisted < validated < sanitized(context) < tainted
 *
 *  A sink declares the MINIMUM context it accepts. A finding is emitted only
 *  when the value's actual state FAILS the sink's requirement — i.e. sanitized
 *  for the WRONG context (or not sanitized at all, but that's the taint engine's
 *  job). It is fully DETERMINISTIC: the lattice is data, not guesses.
 */
import type { ComplexFinding } from "./complex-bugs.js";

/** A true sanitizer/validator: applying it CHANGES the security state. */
interface Sanitizer {
  context: string;
  level: "sanitized" | "validated";
}

/** True sanitizers/validators → the security context they protect against. */
const SANITIZERS: Record<string, Sanitizer> = {
  // --- SQL escaping (correct for string-concatenated SQL) ---
  esc_sql: { context: "sql", level: "sanitized" },
  addslashes: { context: "sql", level: "sanitized" },
  mysqli_real_escape_string: { context: "sql", level: "sanitized" },
  mysql_real_escape_string: { context: "sql", level: "sanitized" },
  pg_escape_string: { context: "sql", level: "sanitized" },
  // --- HTML escaping ---
  sanitize_text_field: { context: "html", level: "sanitized" },
  sanitize_textarea_field: { context: "html", level: "sanitized" },
  esc_html: { context: "html", level: "sanitized" },
  esc_html__: { context: "html", level: "sanitized" },
  htmlspecialchars: { context: "html", level: "sanitized" },
  htmlentities: { context: "html", level: "sanitized" },
  wp_kses: { context: "html", level: "sanitized" },
  wp_kses_post: { context: "html", level: "sanitized" },
  wp_kses_data: { context: "html", level: "sanitized" },
  strip_tags: { context: "html", level: "sanitized" },
  // --- attribute / URL / JSON escaping ---
  esc_attr: { context: "html_attr", level: "sanitized" },
  esc_url: { context: "url", level: "sanitized" },
  esc_url_raw: { context: "url", level: "sanitized" },
  urlencode: { context: "url", level: "sanitized" },
  rawurlencode: { context: "url", level: "sanitized" },
  wp_json_encode: { context: "json", level: "sanitized" },
  json_encode: { context: "json", level: "sanitized" },
  // --- type coercion / validation (stronger than escaping) ---
  absint: { context: "int", level: "validated" },
  intval: { context: "int", level: "validated" },
  sanitize_key: { context: "key", level: "validated" },
  sanitize_email: { context: "email", level: "validated" },
  sanitize_file_name: { context: "filename", level: "validated" },
  filter_var: { context: "validated", level: "validated" },
};

/** Pseudo-sanitizers: transformations that do NOT change the security state.
 *  They are a common source of complex bugs — a dev applies `base64_encode()`
 *  or `trim()` and *believes* the value is now safe when it is still tainted. */
const PSEUDO_SANITIZERS = new Set([
  "trim", "ltrim", "rtrim", "strtolower", "strtoupper", "ucfirst", "ucwords",
  "base64_encode", "base64_decode", "urldecode", "rawurldecode", "stripslashes",
  "html_entity_decode", "htmlspecialchars_decode", "json_decode", "unserialize",
  "serialize", "substr", "mb_substr", "explode", "implode", "str_replace",
  "preg_replace", "nl2br", "strval", "number_format", "sprintf", "md5", "sha1",
  "hash", "crypt", "chr", "ord", "strrev", "str_repeat", "str_pad",
]);

/** Sink type → the security context(s) it accepts. A value must be sanitized
 *  for one of these contexts (or validated/whitelisted) to be safe here. */
const SINK_REQUIREMENTS: Record<string, string[]> = {
  sql_execution: ["sql", "sql_param", "int"],
  code_execution: ["code"],
  command_execution: ["code"],
  deserialization: ["code"],
  file_operations: ["filename"],
  redirect: ["url"],
  html_render: ["html"],
};

const SOURCE_TOKENS = /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|->(input|query|request)\(|\breq\.(query|body|params|headers|cookies)|\bgetParameter\(/;

export interface StateVerdict {
  verdict: "vulnerable" | "safe" | "unknown";
  state: "tainted" | "sanitized" | "validated" | "clean";
  context: string | null;
  required: string[];
  reason: string;
}

/** Compute the deterministic security-state verdict for a flow:
 *  a value with `sanitizers` applied, reaching a sink of `sinkType`. */
export function analyzeSecurityState(input: { sanitizers: string[]; sinkType: string }): StateVerdict {
  let state: StateVerdict["state"] = "tainted";
  let context: string | null = null;
  for (const fn of input.sanitizers) {
    const s = SANITIZERS[fn];
    if (!s) continue; // unknown or pseudo-sanitizer: leaves the value tainted
    if (s.level === "validated") {
      // validation/type-coercion is strictly stronger than escaping
      if (state === "tainted" || state === "sanitized") {
        state = "validated";
        context = s.context;
      }
    } else if (state === "tainted") {
      state = "sanitized";
      context = s.context;
    }
  }

  const required = SINK_REQUIREMENTS[input.sinkType] ?? [];
  if (required.length === 0) {
    return { verdict: "unknown", state, context, required, reason: `sink type '${input.sinkType}' not in the requirements table` };
  }
  if (state === "tainted") {
    return { verdict: "vulnerable", state, context, required, reason: `raw tainted input reaches a ${input.sinkType} sink with no sanitization` };
  }
  if (state === "validated") {
    return { verdict: "safe", state, context, required, reason: `input validated (${context}) — safe for any sink` };
  }
  if (state === "sanitized") {
    if (context && required.includes(context)) {
      return { verdict: "safe", state, context, required, reason: `sanitized for '${context}' — matches sink requirement ${required.join("/")}` };
    }
    return { verdict: "vulnerable", state, context, required, reason: `sanitized for '${context}' but this sink requires ${required.join("/")} — WRONG sanitizer (context mismatch)` };
  }
  return { verdict: "unknown", state, context, required, reason: "unhandled state" };
}

function sinkTypeOf(line: string): string | null {
  // Parameterized (prepare) is the SAFE pattern — not a string-concat sink.
  if (/\$wpdb->(query|get_var|get_row|get_results|get_col)|mysqli_query\s*\(|mysql_query\s*\(|pg_query\s*\(|->query\s*\(/.test(line) && !/->prepare\s*\(/.test(line)) return "sql_execution";
  if (/\b(eval|assert)\s*\(/.test(line)) return "code_execution";
  if (/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/.test(line)) return "command_execution";
  if (/\b(unserialize|maybe_unserialize)\s*\(/.test(line)) return "deserialization";
  if (/\b(file_get_contents|file_put_contents|fopen|readfile|include|require|include_once|require_once)\s*\(/.test(line)) return "file_operations";
  if (/header\s*\(\s*['"]Location/i.test(line)) return "redirect";
  return null;
}

/** Find WRONG-CONTEXT sanitization: a value sanitized for context X reaching a
 *  sink that requires context Y. This is the complex bug binary taint misses. */
export function detectWrongSanitizer(code: string, file: string): ComplexFinding[] {
  const out: ComplexFinding[] = [];
  const ls = code.split("\n");

  // Pass 1: map $var -> sanitizer function applied to a tainted source.
  const varSanitizer = new Map<string, string>(); // var -> sanitizer fn
  for (const line of ls) {
    const m = line.match(/\$(\w+)\s*=\s*([a-zA-Z0-9_]+)\s*\(\s*([^)]*)\s*\)\s*;?/);
    if (!m) continue;
    const [, varName, fn, arg] = m;
    if (!SOURCE_TOKENS.test(arg)) continue; // arg must be attacker-controlled
    if (SANITIZERS[fn]) varSanitizer.set(varName, fn);
    else if (PSEUDO_SANITIZERS.has(fn)) varSanitizer.set(varName, fn); // pseudo — still tainted (tracked to report misuse)
  }

  // Pass 2: a sanitized var reaching a mismatched sink.
  for (let i = 0; i < ls.length; i++) {
    const line = ls[i];
    const sinkType = sinkTypeOf(line);
    if (!sinkType) continue;
    const required = SINK_REQUIREMENTS[sinkType] ?? [];
    for (const [varName, fn] of varSanitizer) {
      if (!new RegExp(`\\$${varName}\\b`).test(line)) continue;
      const sanitizer = SANITIZERS[fn];
      const context = sanitizer?.context ?? null;
      // Correct context (or validation) → safe, no finding.
      if (sanitizer && (sanitizer.level === "validated" || (context && required.includes(context)))) continue;
      const detail = sanitizer
        ? `\$${varName} was sanitized for '${context}' (${fn}()) but this ${sinkType} sink requires ${required.join("/")} — WRONG sanitizer (context mismatch).`
        : `\$${varName} passed through ${fn}() — a NON-sanitizing transformation — and still reaches this ${sinkType} sink as raw tainted input. ${fn}() does not neutralize ${required.join("/")} context.`;
      out.push({
        file,
        line: i + 1,
        type: "wrong_sanitizer",
        category: "Wrong-context sanitization / pseudo-sanitizer",
        severity: "high",
        evidence: line.trim(),
        detail,
      });
    }
  }

  // Dedup by (var, sink line).
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.type}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
