/** EAGLE-EYE data-flow engine (§7-11).
 *
 * Evolves the scanner's source/sink discovery into real data-flow reasoning:
 *
 *   SOURCE → TRANSFORM → VALIDATION → SANITIZER → AUTHORIZATION → CONDITION → SINK
 *
 * The engine answers, for each sink:
 *   - Can an attacker control the source?
 *   - Can the data reach the sink?
 *   - Is the data sanitized or validated?
 *   - Is authorization required before the sink?
 *
 * A dangerous-looking sink after effective sanitization is NOT a finding.
 */
import { readFileSync } from "node:fs";
import { scanFile, AUTH_GATES } from "./scanner.js";

// ---------------------------------------------------------------------------
// Source classification (§8)
// ---------------------------------------------------------------------------

export interface SourceClass {
  /** classifier id, e.g. "http_get" */
  id: string;
  /** human label */
  label: string;
  /** whether this source is directly attacker-controllable */
  attacker_controlled: boolean;
}

export const SOURCES: Record<string, SourceClass> = {
  "$_GET": { id: "http_get", label: "HTTP GET parameter", attacker_controlled: true },
  "$_POST": { id: "http_post", label: "HTTP POST body", attacker_controlled: true },
  "$_REQUEST": { id: "http_request", label: "HTTP request (merged)", attacker_controlled: true },
  "$_COOKIE": { id: "http_cookie", label: "HTTP cookie", attacker_controlled: true },
  "$_FILES": { id: "uploaded_file", label: "Uploaded file", attacker_controlled: true },
  "$_SERVER": { id: "http_header", label: "HTTP header / server env", attacker_controlled: true },
  "file_get_contents('php://input')": { id: "raw_body", label: "Raw request body", attacker_controlled: true },
  "php://input": { id: "raw_body", label: "Raw request body", attacker_controlled: true },
  "json_decode": { id: "json_input", label: "JSON input", attacker_controlled: true },
  "getallheaders": { id: "http_header", label: "HTTP header", attacker_controlled: true },
  "$argv": { id: "cli_argument", label: "CLI argument", attacker_controlled: false },
  "getenv": { id: "environment_variable", label: "Environment variable", attacker_controlled: false },
  "$wpdb->get_results": { id: "database_value", label: "Database value", attacker_controlled: false },
  "wp_remote_get": { id: "external_api", label: "External API data", attacker_controlled: false },
};

/** Classify a source token in a line of code. */
export function classifySource(line: string): SourceClass | null {
  for (const [token, cls] of Object.entries(SOURCES)) {
    if (line.includes(token)) return cls;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sink classification (§9) — security-sensitive operations
// ---------------------------------------------------------------------------

export interface SinkClass {
  /** classifier id, e.g. "sql_execution" */
  id: string;
  /** security category */
  category: string;
  /** CWE suggestion when unsanitized */
  cwe?: string;
}

const SINK_CLASS_MAP: Array<[RegExp, SinkClass]> = [
  [/->query\(|\$wpdb->query|\$wpdb->get_var|\$wpdb->get_results|->whereRaw|->selectRaw|DB::select|DB::raw|DB::statement|DB::insert|DB::update|DB::unprepared/, { id: "sql_execution", category: "SQL execution", cwe: "CWE-89" }],
  [/\beval\(|\bassert\(|\bcreate_function\(|\bcall_user_func\(|\bpreg_replace\(/, { id: "code_execution", category: "Dynamic evaluation / code execution", cwe: "CWE-94" }],
  [/\bsystem\(|\bexec\(|\bshell_exec\(|\bpassthru\(|\bproc_open\(|\bpopen\(/, { id: "command_execution", category: "Command execution", cwe: "CWE-78" }],
  [/\bmove_uploaded_file\(|\bfile_put_contents\(|\bfwrite\(|\bfopen\(|\bunlink\(/, { id: "file_operations", category: "File operations", cwe: "CWE-434" }],
  [/\binclude\(|\brequire\(|\binclude_once\(|\brequire_once\(/, { id: "file_inclusion", category: "File inclusion", cwe: "CWE-98" }],
  [/\bunserialize\(|\bmaybe_unserialize\(/, { id: "deserialization", category: "Deserialization", cwe: "CWE-502" }],
  [/\bwp_remote_get\(|\bwp_remote_post\(|\bfile_get_contents\(|\bcurl_exec\(|\bcurl_setopt\(/, { id: "http_request", category: "HTTP request (SSRF)", cwe: "CWE-918" }],
  [/\bheader\(|\bwp_redirect\(/, { id: "redirect", category: "Redirect handling", cwe: "CWE-601" }],
  [/echo\s|print\s|\bprintf\(/, { id: "html_render", category: "HTML rendering (XSS)", cwe: "CWE-79" }],
  [/\bsimplexml_load_string\(|new SimpleXMLElement|DOMDocument/, { id: "xml_processing", category: "XML processing (XXE)", cwe: "CWE-611" }],
  [/\bZipArchive|\bPharData|->extractTo\(/, { id: "archive_extraction", category: "Archive extraction (zip slip)", cwe: "CWE-22" }],
  [/\bcreateTemplate\(/, { id: "template_injection", category: "Template injection (SSTI)", cwe: "CWE-1336" }],
  [/->xpath\(|DOMXPath/, { id: "xpath_injection", category: "XPath injection", cwe: "CWE-643" }],
  [/\bldap_search\(|\bldap_list\(|\bldap_read\(/, { id: "ldap_injection", category: "LDAP injection", cwe: "CWE-90" }],
];

/** Classify a sink token into a security-sensitive category. */
export function classifySink(sink: string): SinkClass | null {
  for (const [re, cls] of SINK_CLASS_MAP) {
    if (re.test(sink)) return cls;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sanitizer awareness (§10)
// ---------------------------------------------------------------------------

export interface Sanitizer {
  id: string;
  label: string;
  /** the sink categories this sanitizer neutralizes */
  neutralizes: string[];
}

export const SANITIZERS: Record<string, Sanitizer> = {
  "htmlspecialchars": { id: "html_escape", label: "HTML entity encoding", neutralizes: ["html_render"] },
  "esc_html": { id: "html_escape", label: "HTML escape", neutralizes: ["html_render"] },
  "esc_attr": { id: "html_escape", label: "HTML attribute escape", neutralizes: ["html_render"] },
  "htmlentities": { id: "html_escape", label: "HTML entity encoding", neutralizes: ["html_render"] },
  "esc_sql": { id: "sql_escape", label: "SQL escape", neutralizes: ["sql_execution"] },
  "$wpdb->prepare": { id: "sql_prepare", label: "Prepared SQL statement", neutralizes: ["sql_execution"] },
  "->prepare(": { id: "sql_prepare", label: "Prepared statement", neutralizes: ["sql_execution"] },
  "filter_var": { id: "filter_var", label: "Filter input", neutralizes: ["html_render", "sql_execution", "command_execution"] },
  "filter_input": { id: "filter_var", label: "Filter input", neutralizes: ["html_render", "sql_execution", "command_execution"] },
  "sanitize_text_field": { id: "wp_sanitize", label: "WordPress sanitize", neutralizes: ["html_render"] },
  "sanitize_file_name": { id: "wp_sanitize_file", label: "File-name sanitize", neutralizes: ["file_operations", "file_inclusion"] },
  "wp_verify_nonce": { id: "nonce_check", label: "Nonce verification", neutralizes: ["authorization"] },
  "check_ajax_referer": { id: "nonce_check", label: "Nonce verification", neutralizes: ["authorization"] },
  "escapeshellarg": { id: "shell_escape", label: "Shell argument escape", neutralizes: ["command_execution"] },
  "escapeshellcmd": { id: "shell_escape", label: "Shell command escape", neutralizes: ["command_execution"] },
  "intval": { id: "int_cast", label: "Integer cast", neutralizes: ["sql_execution", "command_execution", "file_inclusion"] },
  "absint": { id: "int_cast", label: "Absolute integer cast", neutralizes: ["sql_execution", "command_execution", "file_inclusion"] },
  "preg_replace.*FILTER": { id: "regex_filter", label: "Regex filter", neutralizes: ["html_render"] },
};

/** Find sanitizers present on a line of code. */
export function findSanitizers(line: string): Sanitizer[] {
  const out: Sanitizer[] = [];
  for (const [token, san] of Object.entries(SANITIZERS)) {
    if (line.includes(token)) out.push(san);
  }
  return out;
}

/** Whether a set of sanitizers neutralizes a given sink category. */
export function isSanitized(sanitizers: Sanitizer[], sinkCategory: string): boolean {
  return sanitizers.some((s) => s.neutralizes.includes(sinkCategory) || s.neutralizes.includes("authorization"));
}

// ---------------------------------------------------------------------------
// Data-flow trace (§7)
// ---------------------------------------------------------------------------

export interface FlowEdge {
  source: SourceClass | null;
  transform?: string;
  sanitizers: Sanitizer[];
  /** authorization gates present between source and sink */
  auth_gates: string[];
  sink: SinkClass | null;
  sink_line: number;
  sink_token: string;
}

export interface DataFlowResult {
  file: string;
  /** reachable + unsanitized sinks (genuine candidates) */
  candidates: FlowEdge[];
  /** reachable but sanitized sinks (NOT findings) */
  sanitized: FlowEdge[];
  /** sinks with authorization gates present (lower priority) */
  authorized: FlowEdge[];
}

/**
 * Trace data flow for a single file: for each dangerous sink, look backward to
 * the nearest source, capture transforms/sanitizers/auth gates in between, and
 * classify reachability.
 */
export function traceDataFlow(path: string): DataFlowResult {
  const scan = scanFile(path);
  const result: DataFlowResult = { file: path, candidates: [], sanitized: [], authorized: [] };

  if (scan.error) return result;

  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return result;
  }

  const lines = text.split("\n");

  // Dedup: multiple scanner tokens can match the same sink location (e.g.
  // "$wpdb->query(" and "->query("). Collapse by (sink_category, line).
  const seen = new Set<string>();
  const sinks = scan.sinks.filter((s) => {
    const cls = classifySink(s.sink);
    if (!cls) return false;
    const key = `${cls.id}|${s.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  for (const s of sinks) {
    const sinkClass = classifySink(s.sink)!;

    // SOURCE needs a WIDE window (taint may flow across variable assignments).
    // SANITIZER needs a narrow window (same statement + the sink line itself).
    // AUTH GATE must wrap the sink directly: same line, or the single line above
    // (a `if (check_ajax_referer(...)) {` immediately preceding). A nonce check
    // two+ lines up is a DIFFERENT statement and must not gate this sink.
    const wideStart = Math.max(0, s.line - 15);
    const wideWindow = lines.slice(wideStart, s.line).join("\n");
    const sanitizerWindow = lines.slice(Math.max(0, s.line - 3), s.line + 1).join("\n");
    const sinkLine = lines[s.line - 1] ?? "";
    const prevLine = lines[s.line - 2] ?? "";
    const authContext = sinkLine + "\n" + prevLine;

    const source = classifySource(wideWindow);
    const sanitizers = findSanitizers(sanitizerWindow);
    const authGates = AUTH_GATES.filter((g) => authContext.includes(g));

    const edge: FlowEdge = {
      source,
      sanitizers,
      auth_gates: authGates,
      sink: sinkClass,
      sink_line: s.line,
      sink_token: s.sink,
    };

    // Authorization gates present → lower priority, not a bare candidate.
    if (authGates.length > 0) {
      result.authorized.push(edge);
      continue;
    }
    // Sanitized → NOT a finding.
    if (isSanitized(sanitizers, sinkClass.id)) {
      result.sanitized.push(edge);
      continue;
    }
    result.candidates.push(edge);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Variant analysis (§11) + dedup (§12)
// ---------------------------------------------------------------------------

export interface VariantGroup {
  /** root-cause signature: sink category + source id */
  signature: string;
  root_cause: string;
  sink_category: string;
  cwe?: string;
  /** number of distinct locations sharing the root cause */
  occurrences: number;
  files: string[];
}

/** Group candidate data-flow edges by root cause (sink category + source id). */
export function groupVariants(results: DataFlowResult[]): VariantGroup[] {
  const groups = new Map<string, VariantGroup>();
  for (const r of results) {
    for (const c of r.candidates) {
      const sig = `${c.sink?.category ?? "?"}|${c.source?.id ?? "unknown"}`;
      const g = groups.get(sig);
      if (g) {
        g.occurrences += 1;
        if (!g.files.includes(r.file)) g.files.push(r.file);
      } else {
        groups.set(sig, {
          signature: sig,
          root_cause: `unsanitized ${c.source?.label ?? "unknown"} reaching ${c.sink?.category ?? "sink"}`,
          sink_category: c.sink?.category ?? "?",
          cwe: c.sink?.cwe,
          occurrences: 1,
          files: [r.file],
        });
      }
    }
  }
  return [...groups.values()].sort((a, b) => b.occurrences - a.occurrences);
}
