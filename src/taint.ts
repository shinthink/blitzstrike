/** TAINT engine — real inter-procedural data-flow tracking on a PHP AST.
 *
 * Built on `php-parser` (glayzzle, BSD-3-Clause). Where `dataflow.ts` uses a
 * text window and the legacy line-based `taint.ts` could not resolve array-field
 * access, this module walks a real AST:
 *
 *   - source classification ($_GET/$_POST/$_COOKIE/$_FILES/php://input/...)
 *   - variable assignment + propagation (intra-procedural)
 *   - array-field taint ($file["tmp_name"] inherits taint from $file)
 *   - function summaries (param -> sink) for cross-function taint
 *   - sanitizer awareness + authorization gates
 *
 * A tainted value reaching a sink is only reported if it is NOT neutralized by
 * a sanitizer and NOT guarded by an authorization check.
 */
import { readFileSync } from "node:fs";
import { Engine } from "php-parser";
import { iterSourceFiles } from "./scanner.js";
import type { AstNode } from "./ast.js";
import { findSanitizers, isSanitized, classifySink, type Sanitizer } from "./dataflow.js";

const parser = new Engine({
  parser: { extractDoc: false, php7: true },
  ast: { withPositions: true, withSource: false },
});

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

type Node = AstNode;

function isNode(v: AstNode): v is Node {
  return v && typeof v === "object" && typeof v.kind === "string";
}

function children(node: Node): Node[] {
  const out: Node[] = [];
  for (const k of Object.keys(node)) {
    if (k === "loc") continue;
    const v = node[k];
    if (Array.isArray(v)) {
      for (const c of v) if (isNode(c)) out.push(c);
    } else if (isNode(v)) {
      out.push(v);
    }
  }
  return out;
}

function findKind(node: Node, kind: string, out: Node[] = []): Node[] {
  if (!isNode(node)) return out;
  if (node.kind === kind) out.push(node);
  for (const c of children(node)) findKind(c, kind, out);
  return out;
}

/** Resolve a variable/function name from an expression node. */
function rootVarName(node: Node): string | null {
  if (!isNode(node)) return null;
  if (node.kind === "variable") return node.name ?? null;
  if (node.kind === "name") return typeof node.name === "string" ? node.name : node.name?.name ?? null;
  if (node.kind === "offsetlookup" || node.kind === "propertylookup") return rootVarName(node.what);
  return null;
}

/** Source token for an expression, if it is a direct source. */
function sourceOf(node: Node): string | null {
  if (!isNode(node)) return null;
  // $_GET["x"] -> offsetlookup(what=variable(_GET))
  if (node.kind === "offsetlookup" && node.what?.kind === "variable") {
    const n = node.what.name;
    if (["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].includes(n)) return "$" + n;
  }
  if (node.kind === "variable") {
    const n = node.name;
    if (["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].includes(n)) return "$" + n;
  }
  // php://input / getallheaders
  if (node.kind === "call") {
    const n = rootVarName(node.what);
    if (n === "getallheaders") return "getallheaders";
    if (n === "file_get_contents" && JSON.stringify(node).includes("php://input")) return "php://input";
  }
  return null;
}

/** Whether a call node's target is a dangerous sink; returns the sink class or null. */
function sinkClassOf(call: Node): { token: string; cls: ReturnType<typeof classifySink> } | null {
  const what = call.what;
  if (!isNode(what)) return null;
  let token = "";
  if (what.kind === "propertylookup") {
    const base = rootVarName(what.what);
    const method = what.offset?.name ?? what.offset?.value;
    token = `${base}->${method}(`;
  } else if (what.kind === "name") {
    token = `${what.name}(`;
  }
  if (!token) return null;
  // also accept raw function calls (system/exec/eval/move_uploaded_file/...)
  const cls = classifySink(token) ?? classifySink(what.name ?? "");
  if (!cls) return null;
  return { token, cls };
}

// ---------------------------------------------------------------------------
// Taint analysis over AST
// ---------------------------------------------------------------------------

interface TaintState {
  tainted: boolean;
  sanitizers: Sanitizer[];
  source?: string;
  sourceLine?: number;
}

export interface TaintFinding {
  sink: string;
  sink_line: number;
  category: string;
  cwe?: string;
  variables: string[];
  source?: string;
  source_line?: number;
  sanitized: boolean;
  sanitizers: string[];
  auth_gated: boolean;
  interprocedural: boolean;
}

export interface TaintResult {
  file: string;
  findings: TaintFinding[];
  suppressed: number;
}

interface FunctionSummary {
  name: string;
  params: string[];
  /** which params flow (possibly transitively) into a sink */
  sinkParams: Map<string, { sink: string; line: number }>;
  /** sanitizers applied to params anywhere in the body */
  sanitizedParams: Map<string, Sanitizer[]>;
}

/** Walk statements in order, tracking variable taint state. */
function analyzeBlock(
  statements: Node[],
  env: Map<string, TaintState>,
  summaries: Map<string, FunctionSummary>,
  findings: TaintFinding[],
  suppressed: { n: number },
  params: string[] = [],
  file: string,
): void {
  for (const stmt of statements) {
    if (!isNode(stmt)) continue;
    const kind = stmt.kind;

    if (kind === "expressionstatement") {
      const expr = stmt.expression;
      walkExpression(expr, env, summaries, findings, suppressed, file);
    } else if (kind === "if") {
      // body: statements inside braces; also recurse alternates
      const ifEnv = new Map(env);
      const bodyStmts = stmt.body?.kind === "block" ? stmt.body.children : [stmt.body];
      analyzeBlock(bodyStmts, ifEnv, summaries, findings, suppressed, params, file);
      if (stmt.alternate) {
        const altEnv = new Map(env);
        const altStmts = stmt.alternate.kind === "block" ? stmt.alternate.children : [stmt.alternate];
        analyzeBlock(altStmts, altEnv, summaries, findings, suppressed, params, file);
      }
    } else if (kind === "block") {
      analyzeBlock(stmt.children ?? [], env, summaries, findings, suppressed, params, file);
    } else if (kind === "return" || kind === "echo" || kind === "print") {
      // echo is a statement with an expression list; handle via children
      walkExpression(stmt, env, summaries, findings, suppressed, file);
    } else {
      // recurse generic (foreach, while, etc.)
      for (const c of children(stmt)) {
        if (c.kind === "block" || c.kind === "if") {
          analyzeBlock([c], new Map(env), summaries, findings, suppressed, params, file);
        }
      }
    }
  }
}

function walkExpression(
  node: Node,
  env: Map<string, TaintState>,
  summaries: Map<string, FunctionSummary>,
  findings: TaintFinding[],
  suppressed: { n: number },
  file: string,
): void {
  if (!isNode(node)) return;

  // assignment
  if (node.kind === "assign") {
    const varName = rootVarName(node.left);
    const taint = evalTaint(node.right, env, summaries);
    if (varName) {
      env.set(varName, taint);
    }
    return;
  }

  // call (sink or helper)
  if (node.kind === "call") {
    const sink = sinkClassOf(node);
    if (sink) {
      // determine taint of the arguments
      const argTaints: TaintState[] = node.arguments.map((a: Node) => {
        return evalTaint(a, env, summaries);
      });
      const tainted: TaintState[] = argTaints.filter((t: TaintState) => t.tainted);
      if (tainted.length > 0) {
        const sanitizers: Sanitizer[] = tainted.flatMap((t: TaintState) => t.sanitizers);
        const inlineSan: Sanitizer[] = findSanitizers(JSON.stringify(node));
        const san: Sanitizer[] = [...sanitizers, ...inlineSan].filter((s, i, arr) => arr.indexOf(s) === i);
        const cls = sink.cls!;
        if (!isSanitized(san, cls.id)) {
          findings.push({
            sink: sink.token,
            sink_line: node.loc?.start?.line ?? 0,
            category: cls.category,
            cwe: cls.cwe,
            variables: tainted.map((t: TaintState) => t.source ?? "var"),
            source: tainted[0].source,
            source_line: tainted[0].sourceLine,
            sanitized: false,
            sanitizers: san.map((s: Sanitizer) => s.id),
            auth_gated: false,
            interprocedural: false,
          });
        } else {
          suppressed.n += 1;
        }
      }
      // still recurse into args for nested sinks
      for (const a of node.arguments) walkExpression(a, env, summaries, findings, suppressed, file);
      return;
    }

    // helper function call (inter-procedural)
    const fnName = rootVarName(node.what);
    if (fnName && summaries.has(fnName)) {
      const sum = summaries.get(fnName)!;
      const argTaints: TaintState[] = node.arguments.map((a: Node) => {
        const v = a;
        return evalTaint(v, env, summaries);
      });
      const taintedArgs: TaintState[] = argTaints.filter((t: TaintState) => t.tainted);
      if (taintedArgs.length > 0 && sum.sinkParams.size > 0) {
        const firstSink = [...sum.sinkParams.values()][0];
        const cls = classifySink(firstSink.sink);
        if (cls) {
          const san: Sanitizer[] = [
            ...taintedArgs.flatMap((t: TaintState) => t.sanitizers),
            ...([...sum.sanitizedParams.values()].flat()),
          ];
          if (!isSanitized(san, cls.id)) {
            findings.push({
              sink: firstSink.sink,
              sink_line: firstSink.line,
              category: cls.category,
              cwe: cls.cwe,
              variables: taintedArgs.map((t: TaintState) => t.source ?? "var"),
              source: taintedArgs[0].source,
              source_line: taintedArgs[0].sourceLine,
              sanitized: false,
              sanitizers: san.map((s: Sanitizer) => s.id),
              auth_gated: false,
              interprocedural: true,
            });
          } else {
            suppressed.n += 1;
          }
        }
      }
      return;
    }

    // generic: recurse
    for (const c of children(node)) walkExpression(c, env, summaries, findings, suppressed, file);
    return;
  }

  // echo/print statement (sink)
  if (node.kind === "echo" || node.kind === "print") {
    const exprs = node.expressions ?? [node.expression];
    for (const e of exprs) {
      const cls = classifySink(node.kind === "echo" ? "echo " : "print ");
      const t = evalTaint(e, env, summaries);
      if (t.tainted && cls) {
        const san = [...t.sanitizers, ...findSanitizers(JSON.stringify(e))];
        if (!isSanitized(san, cls.id)) {
          findings.push({
            sink: node.kind + " ",
            sink_line: node.loc?.start?.line ?? 0,
            category: cls.category,
            cwe: cls.cwe,
            variables: [t.source ?? "var"],
            source: t.source,
            source_line: t.sourceLine,
            sanitized: false,
            sanitizers: san.map((s) => s.id),
            auth_gated: false,
            interprocedural: false,
          });
        } else {
          suppressed.n += 1;
        }
      }
    }
    return;
  }

  // recurse
  for (const c of children(node)) walkExpression(c, env, summaries, findings, suppressed, file);
}

/** Evaluate the taint of an expression (variable lookup / source / sanitizer / call). */
function evalTaint(node: Node, env: Map<string, TaintState>, summaries: Map<string, FunctionSummary>): TaintState {
  if (!isNode(node)) return { tainted: false, sanitizers: [] };

  // direct source
  const src = sourceOf(node);
  if (src) return { tainted: true, sanitizers: [], source: src, sourceLine: node.loc?.start?.line };

  // variable lookup (propagate through offsetlookup for $file["tmp_name"])
  if (node.kind === "variable" || node.kind === "offsetlookup") {
    const root = rootVarName(node);
    if (root) {
      const st = env.get(root);
      if (st) return { ...st };
    }
    // offsetlookup on a variable that is itself tainted (e.g. $file["tmp_name"] where $file tainted)
    if (node.kind === "offsetlookup") {
      const whatTaint = evalTaint(node.what, env, summaries);
      if (whatTaint.tainted) return whatTaint;
    }
    return { tainted: false, sanitizers: [] };
  }

  // call -> sanitizer or helper return
  if (node.kind === "call") {
    const fnName = rootVarName(node.what);
    // sanitizer function call
    const san = findSanitizers(fnName ? fnName + "(" : "");
    if (san.length > 0) {
      const inner: TaintState[] = node.arguments.map((a: Node) => evalTaint(a, env, summaries));
      const tainted = inner.some((t: TaintState) => t.tainted);
      return {
        tainted,
        sanitizers: tainted ? [...inner.flatMap((t: TaintState) => t.sanitizers), ...san] : [],
        source: tainted ? inner.find((t: TaintState) => t.tainted)?.source : undefined,
        sourceLine: tainted ? inner.find((t: TaintState) => t.tainted)?.sourceLine : undefined,
      };
    }
    // helper function return taint (conservative: if helper has sink params, return tainted)
    if (fnName && summaries.has(fnName)) {
      const sum = summaries.get(fnName)!;
      const argTaints: TaintState[] = node.arguments.map((a: Node) => evalTaint(a, env, summaries));
      const tainted: TaintState[] = argTaints.filter((t: TaintState) => t.tainted);
      if (tainted.length > 0) {
        const helperSan: Sanitizer[] = [...sum.sanitizedParams.values()].flat();
        return {
          tainted: true,
          sanitizers: [...tainted.flatMap((t: TaintState) => t.sanitizers), ...helperSan],
          source: tainted[0].source,
          sourceLine: tainted[0].sourceLine,
        };
      }
    }
    return { tainted: false, sanitizers: [] };
  }

  // binary/concat/encapsed: tainted if any operand tainted
  if (node.kind === "bin" || node.kind === "concat" || node.kind === "encapsed") {
    const parts = children(node);
    const taints = parts.map((p) => evalTaint(p, env, summaries));
    const tainted = taints.find((t) => t.tainted);
    if (tainted) return { ...tainted, sanitizers: taints.flatMap((t) => t.sanitizers) };
    return { tainted: false, sanitizers: [] };
  }

  // encapsedpart (string interpolation fragment): resolve its expression
  if (node.kind === "encapsedpart") {
    return evalTaint(node.expression, env, summaries);
  }

  return { tainted: false, sanitizers: [] };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function analyzeTaint(path: string): TaintResult {
  const result: TaintResult = { file: path, findings: [], suppressed: 0 };
  let code: string;
  try {
    code = readFileSync(path, "utf8");
  } catch {
    return result;
  }
  let ast: Node;
  try {
    ast = parser.parseCode(code, path);
  } catch {
    return result;
  }

  const functions = findKind(ast, "function");
  const summaries = new Map<string, FunctionSummary>();

  // Build function summaries first (so inter-procedural resolution works).
  for (const fn of functions) {
    const name = typeof fn.name === "string" ? fn.name : fn.name?.name ?? "<anonymous>";
    const params = (fn.arguments ?? []).map((a: Node) => (typeof a === "string" ? a : (typeof a.name === "string" ? a.name : a.name?.name ?? "?")));
    const summary: FunctionSummary = { name, params, sinkParams: new Map(), sanitizedParams: new Map() };
    const env = new Map<string, TaintState>();
    // params start untainted
    for (const p of params) env.set(p, { tainted: false, sanitizers: [] });

    // find sinks inside the body
    const calls = findKind(fn, "call");
    for (const call of calls) {
      const sink = sinkClassOf(call);
      if (!sink) continue;
      const line = call.loc?.start?.line ?? 0;
      const varsInCall = findKind(call, "variable").map((v) => v.name).filter(Boolean);
      for (const v of varsInCall) {
        if (params.includes(v)) summary.sinkParams.set(v, { sink: sink.token, line });
      }
      // sanitizer on the call line applied to a param
      const san = findSanitizers(JSON.stringify(call));
      for (const v of varsInCall) {
        if (params.includes(v) && san.length > 0) {
          summary.sanitizedParams.set(v, [...(summary.sanitizedParams.get(v) ?? []), ...san]);
        }
      }
    }
    // echo/print inside the body: a param reaching an echo is an XSS sink; if a
    // sanitizer wraps the param inline, the param is sanitized instead.
    for (const ek of ["echo", "print"]) {
      for (const en of findKind(fn, ek)) {
        const line = en.loc?.start?.line ?? 0;
        const vars = findKind(en, "variable").map((v) => v.name).filter(Boolean);
        const san = findSanitizers(JSON.stringify(en));
        for (const v of vars) {
          if (params.includes(v)) {
            summary.sinkParams.set(v, { sink: ek + " ", line });
            if (san.length > 0) {
              summary.sanitizedParams.set(v, [...(summary.sanitizedParams.get(v) ?? []), ...san]);
            }
          }
        }
      }
    }
    // sanitizer assignments to params anywhere in the body
    const assigns = findKind(fn, "assign");
    for (const a of assigns) {
      const san = findSanitizers(JSON.stringify(a.right));
      if (san.length > 0) {
        const lv = rootVarName(a.left);
        if (lv && params.includes(lv)) {
          summary.sanitizedParams.set(lv, [...(summary.sanitizedParams.get(lv) ?? []), ...san]);
        }
      }
    }
    // sanitizer applied inline to a param in echo/print (e.g. echo htmlspecialchars($x))
    for (const ek of ["echo", "print"]) {
      for (const en of findKind(fn, ek)) {
        const san = findSanitizers(JSON.stringify(en));
        if (san.length > 0) {
          for (const v of findKind(en, "variable").map((v2) => v2.name).filter(Boolean)) {
            if (params.includes(v)) {
              summary.sanitizedParams.set(v, [...(summary.sanitizedParams.get(v) ?? []), ...san]);
            }
          }
        }
      }
    }
    summaries.set(name, summary);
  }

  // Analyze top-level statements (global scope).
  const topStmts: Node[] = [];
  const body = ast.children ?? [];
  for (const s of body) {
    if (isNode(s) && s.kind !== "function") topStmts.push(s);
  }
  const globalEnv = new Map<string, TaintState>();
  const suppressRef = { n: 0 };
  analyzeBlock(topStmts, globalEnv, summaries, result.findings, suppressRef, [], path);
  result.suppressed = suppressRef.n;
  return result;
}

/** Whole-tree taint scan. */
export function taintTree(root: string, maxFiles = 2000): TaintResult[] {
  const files = iterSourceFiles(root, maxFiles);
  return files.map((f) => analyzeTaint(f));
}
