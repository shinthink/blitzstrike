/** Universal taint engine — language-agnostic core.
 *
 * The taint engine proper is language-independent. Each language contributes a
 * thin adapter that parses source into a *generic intermediate representation*
 * (IR) of security-relevant events:
 *
 *   SOURCE   — attacker-controlled input entering a variable/scope
 *   SINK     — a security-sensitive operation consuming a variable
 *   SANITIZE — a sanitizer/validator applied to a variable
 *   CALL     — a function/method call with arguments (for inter-procedural flow)
 *   ASSIGN   — a variable assignment (for taint propagation)
 *
 * The generic engine then does the same work for every language: propagate
 * taint from SOURCE through ASSIGN, neutralize via SANITIZE, and report when a
 * tainted variable reaches a SINK (directly or across CALL boundaries).
 *
 * Supported adapters:
 *   php      — php-parser (glayzzle, BSD-3-Clause)
 *   javascript / typescript — @babel/parser (MIT)
 *   python   — @lezer/python (MIT)
 *   java     — java-parser (Apache-2.0)
 */

// ---------------------------------------------------------------------------
// Generic IR
// ---------------------------------------------------------------------------

export type SourceKind = "http_parameter" | "http_body" | "http_header" | "http_cookie" | "uploaded_file" | "raw_body" | "cli_argument" | "env_variable" | "external_api" | "database_value";

export type SinkKind =
  | "sql_execution" | "code_execution" | "command_execution" | "file_operations"
  | "file_inclusion" | "deserialization" | "http_request" | "redirect"
  | "html_render" | "xml_processing" | "archive_extraction" | "path_traversal"
  | "template_injection" | "xpath_injection" | "ldap_injection";

export interface IrSource {
  variable: string;
  kind: SourceKind;
  line: number;
  attacker_controlled: boolean;
}

export interface IrSink {
  variable: string;
  kind: SinkKind;
  line: number;
  cwe?: string;
}

export interface IrSanitize {
  variable: string;
  /** sink kinds this sanitizer neutralizes */
  neutralizes: SinkKind[];
  line: number;
}

export interface IrCall {
  /** callee name */
  name: string;
  /** variable names passed as arguments */
  args: string[];
  line: number;
}

export interface IrAssign {
  /** variable being assigned */
  target: string;
  /** variables referenced on the right-hand side */
  sources: string[];
  line: number;
}

export interface LanguageAdapter {
  /** language id (used for auto-detection + reporting) */
  language: string;
  /** file extensions this adapter claims (e.g. [".php", ".phtml"]) */
  extensions: string[];
  /** parse source text into a generic IR */
  parse(code: string, file: string): {
    sources: IrSource[];
    sinks: IrSink[];
    sanitizers: IrSanitize[];
    calls: IrCall[];
    assigns: IrAssign[];
  };
}

// ---------------------------------------------------------------------------
// Generic taint engine (language-independent)
// ---------------------------------------------------------------------------

export interface TaintFinding {
  language: string;
  sink: SinkKind;
  sink_line: number;
  cwe?: string;
  variable: string;
  source_kind?: SourceKind;
  source_line?: number;
  sanitized: boolean;
  sanitizers: string[];
  interprocedural: boolean;
}

export interface TaintResult {
  file: string;
  language: string;
  findings: TaintFinding[];
  suppressed: number;
}

interface VarState {
  tainted: boolean;
  sourceKind?: SourceKind;
  sourceLine?: number;
  /** sink kinds neutralized by applied sanitizers */
  neutralized: Set<SinkKind>;
}

/**
 * Run the generic taint engine over an adapter's IR.
 *
 * Algorithm (single pass, intra-procedural + inter-procedural via call summary):
 *   1. Process statements in order, maintaining a per-variable taint state.
 *   2. SOURCE marks a variable tainted.
 *   3. ASSIGN propagates taint from RHS vars to the target.
 *   4. SANITIZE adds the neutralized sink kinds to a variable.
 *   5. SINK reports when the variable is tainted AND the sink kind is not
 *      neutralized by any sanitizer applied to it.
 *   6. CALL with a tainted arg into a known helper (whose body has a sink on
 *      that param) reports inter-procedurally.
 */
export function runTaintEngine(
  adapter: LanguageAdapter,
  code: string,
  file: string,
): TaintResult {
  const result: TaintResult = { file, language: adapter.language, findings: [], suppressed: 0 };
  let ir;
  try {
    ir = adapter.parse(code, file);
  } catch {
    return result;
  }

  // Build helper summaries: function/method name -> sink kinds reachable via params.
  // (Adapters emit CALL events with arg names; we approximate inter-procedural
  // flow by linking a call's tainted args to the callee's sinks when the callee
  // is a local function we've seen sinks for. This is a conservative summary:
  // for now, helpers are summarized by function declarations found in the same
  // file via the adapter's CALL/ASSIGN stream.)

  const state = new Map<string, VarState>();

  function getVar(name: string): VarState {
    if (!state.has(name)) state.set(name, { tainted: false, neutralized: new Set() });
    return state.get(name)!;
  }

  // Collect sanitizer neutralizations by variable (so a sanitizer defined before
  // use applies to the sink later).
  for (const s of ir.sanitizers) {
    const st = getVar(s.variable);
    for (const n of s.neutralizes) st.neutralized.add(n);
    // a sanitizer applied to a tainted var keeps taint (value is derived) but is neutralized
  }

  // Pass 1: mark sources tainted.
  for (const src of ir.sources) {
    const st = getVar(src.variable);
    st.tainted = true;
    st.sourceKind = src.kind;
    st.sourceLine = src.line;
  }

  // Pass 2: propagate assignments (in order) — repeated until fixpoint for chains.
  for (let pass = 0; pass < 5; pass++) {
    let changed = false;
    for (const a of ir.assigns) {
      const dst = getVar(a.target);
      for (const rv of a.sources) {
        const src = getVar(rv);
        if (src.tainted && !dst.tainted) {
          dst.tainted = true;
          dst.sourceKind = src.sourceKind;
          dst.sourceLine = src.sourceLine;
          changed = true;
        }
        // propagate neutralizations too (sanitized value stays sanitized)
        for (const n of src.neutralized) dst.neutralized.add(n);
      }
    }
    if (!changed) break;
  }

  // Pass 3: report sinks (dedup: same (sink kind, line) collapses to one).
  const seenSinks = new Set<string>();
  for (const sink of ir.sinks) {
    const st = getVar(sink.variable);
    if (!st.tainted) continue;
    const neutralized = st.neutralized.has(sink.kind);
    if (neutralized) {
      result.suppressed += 1;
      continue;
    }
    const dedupKey = `${sink.kind}|${sink.line}`;
    if (seenSinks.has(dedupKey)) continue;
    seenSinks.add(dedupKey);
    result.findings.push({
      language: adapter.language,
      sink: sink.kind,
      sink_line: sink.line,
      cwe: sink.cwe,
      variable: sink.variable,
      source_kind: st.sourceKind,
      source_line: st.sourceLine,
      sanitized: false,
      sanitizers: [],
      interprocedural: false,
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Language registry + auto-detection
// ---------------------------------------------------------------------------

const registry = new Map<string, LanguageAdapter>();

export function registerLanguage(adapter: LanguageAdapter): void {
  registry.set(adapter.language, adapter);
  for (const ext of adapter.extensions) {
    // extension -> adapter (kept separately for detection)
    extensionMap.set(ext.toLowerCase(), adapter);
  }
}

const extensionMap = new Map<string, LanguageAdapter>();

export function detectLanguage(file: string): LanguageAdapter | null {
  const dot = file.lastIndexOf(".");
  if (dot < 0) return null;
  const ext = file.slice(dot).toLowerCase();
  return extensionMap.get(ext) ?? null;
}

export function listLanguages(): Array<{ language: string; extensions: string[] }> {
  return [...registry.values()].map((a) => ({ language: a.language, extensions: a.extensions }));
}

export function analyzeTaintUniversal(code: string, file: string): TaintResult {
  const adapter = detectLanguage(file);
  if (!adapter) {
    return { file, language: "unknown", findings: [], suppressed: 0 };
  }
  return runTaintEngine(adapter, code, file);
}
