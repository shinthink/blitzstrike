/** EAGLE-EYE 2.0 — whole-program interprocedural taint on a PHP AST.
 *
 * Builds on the call graph (`callgraph.ts`) and the sink/sanitizer taxonomy
 * (`dataflow.ts`) to answer, soundly, *"does a tainted value reach a sink, and
 * is it neutralized?"* across function boundaries. Key upgrades over the v1
 * taint engine:
 *
 *   - return propagation: `$x = helper($tainted)` taints `$x` iff `helper`
 *     returns a value derived from its parameter
 *   - alias tracking: `$a = &$b` shares taint (references), object-property taint
 *   - conditional flow: ternary + if/else branches are merged
 *   - authorization flow: sinks guarded by a capability/nonce check are flagged
 *   - transitive interprocedural flow via a call-graph worklist
 */
import { readFileSync } from "node:fs";
import { Engine } from "php-parser";
import type { AstNode } from "./ast.js";
import { classifySink, findSanitizers, isSanitized, type Sanitizer, type SinkClass } from "./dataflow.js";
import { AUTH_GATES } from "./scanner.js";
import { buildCallGraph, entryPoints, reachableFrom } from "./callgraph.js";
import { getCache, setCache } from "./cache.js";

const parser = new Engine({
  parser: { extractDoc: false, php7: true },
  ast: { withPositions: true, withSource: false },
});

type Node = AstNode;

function isNode(v: unknown): v is Node {
  return !!v && typeof v === "object" && typeof (v as Node).kind === "string";
}

function children(node: Node): Node[] {
  const out: Node[] = [];
  for (const k of Object.keys(node)) {
    if (k === "loc") continue;
    const v = (node as Record<string, unknown>)[k];
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

function nameOf(node: unknown): string | null {
  if (!isNode(node)) return null;
  if (typeof node.name === "string") return node.name;
  if (isNode(node.name)) return nameOf(node.name);
  return null;
}

function rootVarName(node: Node): string | null {
  if (!isNode(node)) return null;
  if (node.kind === "variable") return node.name ?? null;
  if (node.kind === "name") return typeof node.name === "string" ? node.name : node.name?.name ?? null;
  if (node.kind === "offsetlookup" || node.kind === "propertylookup") return rootVarName(node.what);
  return null;
}

// Callee name for a call target: method name for $obj->method()/Class::method(),
// function name for func(). Unlike rootVarName (which walks to the object
// variable), this returns the NAME being called so interprocedural resolution
// can match method definitions.
function calleeName(what: Node): string | null {
  if (!isNode(what)) return null;
  if (what.kind === "name") return typeof what.name === "string" ? what.name : what.name?.name ?? null;
  if (what.kind === "propertylookup" || what.kind === "staticlookup") return what.offset?.name ?? what.offset?.value ?? null;
  return null;
}

// Built-in functions whose return value is derived from their arguments, so
// taint propagates through them. Covers the array→string (`implode`/`join`) and
// format-string (`sprintf`) patterns that dominate framework query builders.
const TAINT_PROPAGATING_BUILTINS = new Set([
  "implode", "join", "sprintf", "vsprintf",
  "str_replace", "str_ireplace", "substr", "mb_substr", "substr_replace",
  "trim", "ltrim", "rtrim", "strtolower", "strtoupper", "ucfirst", "lcfirst",
  "urldecode", "rawurldecode", "base64_decode", "html_entity_decode",
  "stripslashes", "addslashes", "strval", "preg_quote", "nl2br",
]);

function sourceOf(node: Node): string | null {
  if (!isNode(node)) return null;
  if (node.kind === "offsetlookup" && node.what?.kind === "variable") {
    const n = node.what.name;
    if (["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].includes(n)) return "$" + n;
  }
  if (node.kind === "variable") {
    const n = node.name;
    if (["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].includes(n)) return "$" + n;
  }
  if (node.kind === "call") {
    const n = rootVarName(node.what);
    if (n === "getallheaders") return "getallheaders";
    if (n === "file_get_contents" && JSON.stringify(node).includes("php://input")) return "php://input";
    // Framework request accessors: $request->input() / $req->query() / ->get() / ->post() / ...
    if (node.what?.kind === "propertylookup") {
      const method = node.what.offset?.name ?? node.what.offset?.value;
      const base = rootVarName(node.what.what);
      const reqMethods = ["input", "query", "get", "post", "all", "json", "cookie", "file", "header", "only", "except", "server"];
      if (base && /^(request|req)$/i.test(base) && reqMethods.includes(String(method))) {
        return `$${base}->${method}()`;
      }
    }
  }
  return null;
}

function sinkClassOf(call: Node): { token: string; cls: SinkClass } | null {
  const what = call.what;
  if (!isNode(what)) return null;
  let token = "";
  if (what.kind === "propertylookup") {
    const baseNode = what.what;
    const base = rootVarName(baseNode);
    const method = what.offset?.name ?? what.offset?.value;
    // PHP variables carry a `$` prefix in source; the AST stores the bare name.
    const baseStr = isNode(baseNode) && (baseNode.kind === "variable" || baseNode.kind === "offsetlookup") ? `$${base}` : base;
    token = `${baseStr}->${method}(`;
  } else if (what.kind === "name") {
    token = `${what.name}(`;
  } else if (what.kind === "staticlookup") {
    // Static method call: DB::select(), DB::raw(), SomeClass::method()
    const clsName = nameOf(what.what);
    const method = what.offset?.name ?? what.offset?.value;
    if (clsName && method) token = `${clsName}::${method}(`;
  }
  if (!token) return null;
  const cls = classifySink(token) ?? classifySink(what.name ?? "");
  if (!cls) return null;
  return { token, cls };
}

// ---------------------------------------------------------------------------
// Taint state
// ---------------------------------------------------------------------------

interface TaintState {
  tainted: boolean;
  sources: string[];
  sanitizers: Sanitizer[];
  sourceLine?: number;
}

const CLEAN: TaintState = { tainted: false, sources: [], sanitizers: [] };

function mergeTaint(...states: TaintState[]): TaintState {
  const taintedStates = states.filter((s) => s.tainted);
  if (taintedStates.length === 0) return CLEAN;
  // Sources: UNION (tainted if ANY path taints).
  const sources = [...new Set(taintedStates.flatMap((s) => s.sources))];
  // Sanitizers: INTERSECTION (sanitized only if EVERY path sanitizes — sound).
  let sanitizers: Sanitizer[] = taintedStates[0].sanitizers;
  for (const s of taintedStates.slice(1)) {
    sanitizers = sanitizers.filter((san) => s.sanitizers.some((x) => x.id === san.id));
  }
  return {
    tainted: true,
    sources,
    sanitizers,
    sourceLine: taintedStates.find((s) => s.sourceLine !== undefined)?.sourceLine,
  };
}

// ---------------------------------------------------------------------------
// Function summary
// ---------------------------------------------------------------------------

interface SinkHit {
  sink: string;
  line: number;
  sanitized: boolean;
  authGated: boolean;
  authGates: string[];
}

interface ParamCall {
  callee: string;
  argIndex: number;
  line: number;
}

interface FuncSummary {
  id: string;
  name: string;
  params: string[];
  /** params declared by-reference (`&$x`) — these alias the caller's variable */
  byrefParams: Set<string>;
  /** param name -> direct sink hits in the body */
  paramSinks: Map<string, SinkHit[]>;
  /** params that flow to the return value */
  paramReturns: Set<string>;
  /** param name -> calls where that param is passed as an argument */
  paramCalls: Map<string, ParamCall[]>;
  /** byref param -> sources written to it (output-parameter taint) */
  paramWrites: Map<string, string[]>;
  /** sink hits reached from sources INSIDE the body (superglobals, $request->input(), …) */
  internalSinks: SinkHit[];
}

interface AnalyzeCtx {
  sinks: SinkHit[];
  returnsTainted: boolean;
  calls: ParamCall[];
}

function summarizeFunction(fn: Node, id: string, name: string, summaries: Map<string, FuncSummary>): FuncSummary {
  const params: string[] = (fn.arguments ?? []).map((a: Node) => nameOf(a) ?? "?");
  const byrefParams = new Set<string>();
  (fn.arguments ?? []).forEach((a: Node, i: number) => {
    if (a.byref === true) byrefParams.add(params[i]);
  });
  const summary: FuncSummary = { id, name, params, byrefParams, paramSinks: new Map(), paramReturns: new Set(), paramCalls: new Map(), paramWrites: new Map(), internalSinks: [] };
  const bodyStmts: Node[] = fn.body?.kind === "block" ? fn.body.children ?? [] : [fn.body];

  // Internal-source pass: detect sinks reached from sources declared INSIDE the
  // body (superglobals, $request->input(), …) with all params CLEAN. This is
  // how framework controllers (Laravel/Symfony) read user input.
  {
    const cleanEnv = new Map<string, TaintState>();
    for (const p of params) cleanEnv.set(p, CLEAN);
    const cleanCtx: AnalyzeCtx = { sinks: [], returnsTainted: false, calls: [] };
    analyzeBody(bodyStmts, cleanEnv, summary, cleanCtx, "", new Map(), [], summaries);
    summary.internalSinks = cleanCtx.sinks;
  }

  for (const p of params) {
    const env = new Map<string, TaintState>();
    for (const q of params) env.set(q, CLEAN);
    env.set(p, { tainted: true, sources: [`arg:${p}`], sanitizers: [] });
    const ctx: AnalyzeCtx = { sinks: [], returnsTainted: false, calls: [] };
    analyzeBody(bodyStmts, env, summary, ctx, p, new Map(), [], summaries);
    summary.paramSinks.set(p, ctx.sinks);
    if (ctx.returnsTainted) summary.paramReturns.add(p);
    summary.paramCalls.set(p, ctx.calls);
    // byref output: if the body overwrote a byref param with a real source,
    // record it so callers can taint their variable.
    if (byrefParams.has(p)) {
      const finalTaint = env.get(p);
      const written = finalTaint?.sources.filter((s) => !s.startsWith("arg:")) ?? [];
      if (written.length > 0) summary.paramWrites.set(p, written);
    }
  }
  return summary;
}

function analyzeBody(
  statements: Node[],
  env: Map<string, TaintState>,
  summary: FuncSummary,
  ctx: AnalyzeCtx,
  taintedParam: string,
  props: Map<string, Map<string, TaintState>>,
  activeAuth: string[],
  summaries: Map<string, FuncSummary>,
  validating = false,
): void {
  for (const stmt of statements) {
    if (!isNode(stmt)) continue;
    const kind = stmt.kind;

    if (kind === "expressionstatement") {
      analyzeExpr(stmt.expression, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    } else if (kind === "if") {
      const condGates = authGatesOf(stmt.test);
      const branchAuth = [...activeAuth, ...condGates];
      const condValidating = validationGatesOf(stmt.test);
      const thenStmts = stmt.body?.kind === "block" ? stmt.body.children ?? [] : [stmt.body];
      const thenEnv = cloneEnv(env);
      const thenCtx: AnalyzeCtx = { sinks: [], returnsTainted: false, calls: [] };
      analyzeBody(thenStmts, thenEnv, summary, thenCtx, taintedParam, cloneProps(props), branchAuth, summaries, validating || condValidating);
      mergeCtx(ctx, thenCtx);
      if (stmt.alternate) {
        const altStmts = stmt.alternate.kind === "block" ? stmt.alternate.children ?? [] : [stmt.alternate];
        const altEnv = cloneEnv(env);
        const altCtx: AnalyzeCtx = { sinks: [], returnsTainted: false, calls: [] };
        analyzeBody(altStmts, altEnv, summary, altCtx, taintedParam, cloneProps(props), activeAuth, summaries, validating);
        mergeCtx(ctx, altCtx);
        for (const [k, v] of thenEnv) {
          const alt = altEnv.get(k);
          env.set(k, alt ? mergeTaint(v, alt) : v);
        }
      } else {
        for (const [k, v] of thenEnv) env.set(k, v);
      }
    } else if (kind === "block") {
      analyzeBody(stmt.children ?? [], env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    } else if (kind === "return") {
      const t = analyzeExpr(stmt.expr, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
      if (t.tainted) ctx.returnsTainted = true;
    } else if (kind === "echo" || kind === "print") {
      analyzeExpr(stmt, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    } else {
      for (const c of children(stmt)) {
        if (c.kind === "block" || c.kind === "if") {
          analyzeBody([c], env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
        } else {
          analyzeExpr(c, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
        }
      }
    }
  }
}

function analyzeExpr(
  node: Node,
  env: Map<string, TaintState>,
  summary: FuncSummary,
  ctx: AnalyzeCtx,
  taintedParam: string,
  props: Map<string, Map<string, TaintState>>,
  activeAuth: string[],
  summaries: Map<string, FuncSummary>,
  validating = false,
): TaintState {
  if (!isNode(node)) return CLEAN;

  // Source detection FIRST: `$_GET['u']` is both an offsetlookup AND a source.
  const src = sourceOf(node);
  if (src) return { tainted: true, sources: [src], sanitizers: [], sourceLine: node.loc?.start?.line };

  // cast: (array) / (string) / (int) … propagate taint from the operand. An
  // integer cast is a sanitizer (neutralizes sql/command/file sinks); array and
  // string casts are NOT (a string can still carry a payload through them).
  if (node.kind === "cast") {
    const inner = analyzeExpr(node.expr, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    const castType = String(node.type ?? "");
    if (/^(int|integer|bool|boolean|float|double)$/i.test(castType) && inner.tainted) {
      return { ...inner, sanitizers: [...inner.sanitizers, { id: "int_cast", label: "Numeric cast", neutralizes: ["sql_execution", "command_execution", "file_inclusion"] }] };
    }
    return inner;
  }

  // assignment
  if (node.kind === "assign") {
    const byref = node.operator === "=&";
    const rhs = analyzeExpr(node.right, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    const lhs = node.left;
    if (isNode(lhs) && lhs.kind === "variable") {
      const varName = lhs.name;
      if (byref) {
        const refVar = rootVarName(node.right);
        if (refVar) {
          const refTaint = env.get(refVar) ?? rhs;
          env.set(varName, refTaint);
          env.set(refVar, refTaint);
        } else {
          env.set(varName, rhs);
        }
      } else {
        env.set(varName, rhs);
      }
    } else if (isNode(lhs) && lhs.kind === "propertylookup") {
      const objName = rootVarName(lhs.what);
      const propName = lhs.offset?.name ?? "?";
      if (objName) {
        let oprops = props.get(objName);
        if (!oprops) {
          oprops = new Map();
          props.set(objName, oprops);
        }
        oprops.set(propName, rhs);
      }
    }
    return rhs;
  }

  // call
  if (node.kind === "call") {
    const sink = sinkClassOf(node);
    const argTaints: TaintState[] = node.arguments.map((a: Node) => analyzeExpr(a, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating));
    const taintedArgs = argTaints.filter((t) => t.tainted);

    if (sink) {
      if (taintedArgs.length > 0) {
        const san: Sanitizer[] = [...taintedArgs.flatMap((t) => t.sanitizers), ...findSanitizers(JSON.stringify(node))];
        const sanitized = isSanitized(san, sink.cls.id);
        const gates = activeAuth;
        ctx.sinks.push({ sink: sink.token, line: node.loc?.start?.line ?? 0, sanitized, authGated: gates.length > 0, authGates: gates });
      }
      for (const a of node.arguments) analyzeExpr(a, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
      return taintedArgs.length > 0 ? mergeTaint(...taintedArgs) : CLEAN;
    }

    // helper call
    const fnName = calleeName(node.what);
    if (fnName) {
      // Built-in taint-propagating functions: implode/join/sprintf … return a
      // value derived from their arguments, so taint flows through them.
      if (TAINT_PROPAGATING_BUILTINS.has(fnName) && taintedArgs.length > 0) {
        return mergeTaint(...taintedArgs);
      }
      // sanitizer call (htmlspecialchars, esc_html, intval, ...): apply the
      // sanitizer to the tainted argument and propagate taint + sanitizer.
      const san = findSanitizers(fnName + "(");
      if (san.length > 0) {
        if (taintedArgs.length > 0) {
          return mergeTaint(...taintedArgs.map((t) => ({ ...t, sanitizers: [...t.sanitizers, ...san] })));
        }
        return CLEAN;
      }
      // record param->call edge for transitive propagation
      for (let i = 0; i < node.arguments.length; i++) {
        const argVar = rootVarName(node.arguments[i]);
        if (argVar === taintedParam) {
          ctx.calls.push({ callee: fnName, argIndex: i, line: node.loc?.start?.line ?? 0 });
        }
      }
      // return propagation: if a tainted arg's corresponding param flows to the
      // helper's return value, the call result is tainted.
      const helperId = resolveFuncId(fnName, summaries);
      const helperSum = helperId ? summaries.get(helperId) : undefined;
      if (helperSum && taintedArgs.length > 0) {
        for (let i = 0; i < node.arguments.length; i++) {
          if (argTaints[i]?.tainted) {
            const paramName = helperSum.params[i];
            if (paramName && helperSum.paramReturns.has(paramName)) {
              return mergeTaint(...taintedArgs);
            }
          }
        }
      }
      // byref output: if the helper WRITES a source to a byref param, taint the
      // caller's variable passed at that position.
      if (helperSum && helperSum.paramWrites.size > 0) {
        for (let i = 0; i < node.arguments.length; i++) {
          const paramName = helperSum.params[i];
          if (!paramName || !helperSum.paramWrites.has(paramName)) continue;
          const argVar = rootVarName(node.arguments[i]);
          const written = helperSum.paramWrites.get(paramName)!;
          if (argVar) {
            env.set(argVar, { tainted: true, sources: written, sanitizers: [] });
          }
        }
      }
    }
    // method chain: recurse into the base so nested sinks are detected
    // (e.g. DB::table()->whereRaw(...)->get() — whereRaw is the real sink)
    if (isNode(node.what) && node.what.kind === "propertylookup") {
      analyzeExpr(node.what, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    }
    return CLEAN;
  }

  // variable / offsetlookup / propertylookup lookup
  if (node.kind === "variable") {
    const t = env.get(node.name);
    return t ? { ...t } : CLEAN;
  }
  if (node.kind === "offsetlookup") {
    const root = rootVarName(node);
    if (root) {
      const t = env.get(root);
      if (t) return { ...t };
    }
    return analyzeExpr(node.what, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
  }
  if (node.kind === "propertylookup") {
    const objName = rootVarName(node.what);
    const propName = node.offset?.name ?? "?";
    if (objName) {
      const pt = props.get(objName)?.get(propName);
      if (pt) return { ...pt };
    }
    return analyzeExpr(node.what, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
  }

  // ternary (php-parser calls it `retif`): merge both branches
  if (node.kind === "retif") {
    const t = analyzeExpr(node.trueExpr ?? node.test, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    const f = node.falseExpr ? analyzeExpr(node.falseExpr, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating) : CLEAN;
    return mergeTaint(t, f);
  }

  // binary / concat / encapsed
  if (node.kind === "bin" || node.kind === "concat" || node.kind === "encapsed") {
    const parts = children(node);
    const taints = parts.map((p) => analyzeExpr(p, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating));
    return mergeTaint(...taints);
  }

  if (node.kind === "encapsedpart") {
    return analyzeExpr(node.expression, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
  }

  // echo/print statement
  if (node.kind === "echo" || node.kind === "print") {
    const exprs = node.expressions ?? [node.expression];
    const cls = classifySink(node.kind === "echo" ? "echo " : "print ");
    let ret = CLEAN;
    for (const e of exprs) {
      const t = analyzeExpr(e, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
      if (t.tainted && cls) {
        const san = [...t.sanitizers, ...findSanitizers(JSON.stringify(e))];
        ctx.sinks.push({ sink: node.kind + " ", line: node.loc?.start?.line ?? 0, sanitized: isSanitized(san, cls.id) || validating, authGated: activeAuth.length > 0, authGates: activeAuth });
      }
      ret = mergeTaint(ret, t);
    }
    return ret;
  }

  // include/require/include_once/require_once (statement nodes, not calls)
  if (node.kind === "include") {
    const base = node.require ? "require" : "include";
    const suffix = node.once ? "_once" : "";
    const sinkToken = base + suffix + "(";
    const cls = classifySink(sinkToken);
    const t = analyzeExpr(node.target, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    if (t.tainted && cls) {
      const san = [...t.sanitizers, ...findSanitizers(JSON.stringify(node))];
      ctx.sinks.push({ sink: sinkToken, line: node.loc?.start?.line ?? 0, sanitized: isSanitized(san, cls.id) || validating, authGated: activeAuth.length > 0, authGates: activeAuth });
    }
    return t;
  }

  // eval (statement node, not a call)
  if (node.kind === "eval") {
    const cls = classifySink("eval(");
    const t = analyzeExpr(node.source, env, summary, ctx, taintedParam, props, activeAuth, summaries, validating);
    if (t.tainted && cls) {
      ctx.sinks.push({ sink: "eval(", line: node.loc?.start?.line ?? 0, sanitized: false, authGated: activeAuth.length > 0, authGates: activeAuth });
    }
    return t;
  }

  return CLEAN;
}

function cloneEnv(env: Map<string, TaintState>): Map<string, TaintState> {
  return new Map([...env.entries()].map(([k, v]) => [k, { ...v, sources: [...v.sources], sanitizers: [...v.sanitizers] }]));
}

function cloneProps(props: Map<string, Map<string, TaintState>>): Map<string, Map<string, TaintState>> {
  const out = new Map<string, Map<string, TaintState>>();
  for (const [k, v] of props) out.set(k, new Map(v));
  return out;
}

function mergeCtx(ctx: AnalyzeCtx, other: AnalyzeCtx): void {
  ctx.sinks.push(...other.sinks);
  if (other.returnsTainted) ctx.returnsTainted = true;
  ctx.calls.push(...other.calls);
}

function authGatesOf(node: Node): string[] {
  if (!isNode(node)) return [];
  return AUTH_GATES.filter((g) => JSON.stringify(node).includes(g));
}

const VALIDATION_GATES = ["in_array", "preg_match", "ctype_digit", "ctype_alnum", "is_numeric"];

function validationGatesOf(node: Node): boolean {
  if (!isNode(node)) return false;
  const text = JSON.stringify(node);
  return VALIDATION_GATES.some((g) => text.includes(g));
}

// ---------------------------------------------------------------------------
// Declaration collection + resolution
// ---------------------------------------------------------------------------

function collectDecls(ast: Node, out: Array<{ id: string; name: string; node: Node; kind: "function" | "method" }>): void {
  walkDecls(ast, out);
}

function walkDecls(node: Node, out: Array<{ id: string; name: string; node: Node; kind: "function" | "method" }>, className?: string): void {
  if (!isNode(node)) return;
  if (node.kind === "function") {
    const name = nameOf(node.name);
    if (name) out.push({ id: `func:${name}`, name, node, kind: "function" });
  } else if (node.kind === "class") {
    const cn = nameOf(node.name);
    for (const c of children(node)) {
      if (c.kind === "method") {
        const mn = nameOf(c.name);
        if (mn && cn) out.push({ id: `method:${cn}::${mn}`, name: mn, node: c, kind: "method" });
      }
    }
    return;
  } else if (node.kind === "method") {
    const mn = nameOf(node.name);
    if (mn && className) out.push({ id: `method:${className}::${mn}`, name: mn, node, kind: "method" });
  }
  const childCtx = node.kind === "class" ? nameOf(node.name) ?? className : className;
  for (const c of children(node)) walkDecls(c, out, childCtx);
}

function resolveFuncId(name: string, summaries: Map<string, FuncSummary>): string | null {
  if (summaries.has(`func:${name}`)) return `func:${name}`;
  for (const [id, s] of summaries) {
    if (s.name === name && id.startsWith("method:")) return id;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface Eagle2Finding {
  sink: string;
  sink_line: number;
  category: string;
  cwe?: string;
  source?: string;
  source_line?: number;
  sanitized: boolean;
  auth_gated: boolean;
  auth_gates: string[];
  interprocedural: boolean;
  via_return: boolean;
  internal_source?: boolean;
}

export interface Eagle2Result {
  file: string;
  findings: Eagle2Finding[];
  suppressed: number;
  summary: { functions: number; methods: number; edges: number; entry_points: string[]; unreachable: string[] };
}

export function analyzeDataFlow2(path: string): Eagle2Result {
  // Cache: reuse a prior result for unchanged source (keyed by content hash + engine version).
  let cacheCode = "";
  try {
    cacheCode = readFileSync(path, "utf8");
  } catch {
    /* unreadable — skip cache */
  }
  if (cacheCode) {
    const cached = getCache<Eagle2Result>("eagle2", cacheCode);
    if (cached) return cached;
  }

  const cg = buildCallGraph(path);
  const entries = entryPoints(cg);
  const reachable = new Set<string>();
  for (const e of entries) for (const n of reachableFrom(cg, e)) reachable.add(n);
  const unreachable = [...cg.nodes.keys()].filter((id) => !reachable.has(id));
  const result: Eagle2Result = {
    file: path,
    findings: [],
    suppressed: 0,
    summary: { functions: 0, methods: 0, edges: cg.edges.length, entry_points: entries, unreachable },
  };

  let code: string;
  try {
    code = cacheCode || readFileSync(path, "utf8");
  } catch {
    return result;
  }
  let ast: Node;
  try {
    ast = parser.parseCode(code, path) as Node;
  } catch {
    return result;
  }

  // Summarize all functions + methods.
  const summaries = new Map<string, FuncSummary>();
  const decls: Array<{ id: string; name: string; node: Node; kind: "function" | "method" }> = [];
  collectDecls(ast, decls);
  for (const d of decls) {
    summaries.set(d.id, summarizeFunction(d.node, d.id, d.name, summaries));
    if (d.kind === "function") result.summary.functions += 1;
    else result.summary.methods += 1;
  }

  // Analyze top-level (main) with real source taint.
  const topStmts: Node[] = [];
  for (const s of ast.children ?? []) {
    if (isNode(s) && s.kind !== "function" && s.kind !== "class") topStmts.push(s);
  }
  const mainSummary: FuncSummary = { id: "main", name: "main", params: [], byrefParams: new Set(), paramSinks: new Map(), paramReturns: new Set(), paramCalls: new Map(), paramWrites: new Map(), internalSinks: [] };
  const mainEnv = new Map<string, TaintState>();
  const mainCtx: AnalyzeCtx = { sinks: [], returnsTainted: false, calls: [] };
  const mainProps = new Map<string, Map<string, TaintState>>();
  analyzeBody(topStmts, mainEnv, mainSummary, mainCtx, "", mainProps, [], summaries);

  // Emit direct (main-scope) sink hits.
  for (const hit of mainCtx.sinks) {
    const cls = classifySink(hit.sink);
    if (!cls) continue;
    if (hit.sanitized) {
      result.suppressed += 1;
      continue;
    }
    result.findings.push({
      sink: hit.sink,
      sink_line: hit.line,
      category: cls.category,
      cwe: cls.cwe,
      sanitized: false,
      auth_gated: hit.authGated,
      auth_gates: hit.authGates,
      interprocedural: false,
      via_return: false,
    });
  }

  // Worklist: propagate main's tainted call arguments through the call graph.
  const queue: Array<{ funcId: string; param: string; source: string; sourceLine?: number; viaReturn: boolean }> = [];
  const seen = new Set<string>();

  // Seed: helper calls made in main with tainted arguments.
  const mainCalls = topStmts.flatMap((s) => findKind(s, "call"));
  for (const call of mainCalls) {
    const fnName = calleeName(call.what);
    if (!fnName || sinkClassOf(call)) continue;
    const target = resolveFuncId(fnName, summaries);
    if (!target) continue;
    for (let i = 0; i < call.arguments.length; i++) {
      const argTaint = analyzeExpr(call.arguments[i], mainEnv, mainSummary, mainCtx, "", mainProps, [], summaries);
      if (argTaint.tainted) {
        const param = summaries.get(target)!.params[i];
        if (param) queue.push({ funcId: target, param, source: argTaint.sources[0], sourceLine: argTaint.sourceLine, viaReturn: false });
      }
    }
  }

  while (queue.length) {
    const item = queue.shift()!;
    const key = `${item.funcId}:${item.param}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const sum = summaries.get(item.funcId);
    if (!sum) continue;

    for (const hit of sum.paramSinks.get(item.param) ?? []) {
      const cls = classifySink(hit.sink);
      if (!cls) continue;
      if (hit.sanitized) {
        result.suppressed += 1;
        continue;
      }
      result.findings.push({
        sink: hit.sink,
        sink_line: hit.line,
        category: cls.category,
        cwe: cls.cwe,
        source: item.source,
        source_line: item.sourceLine,
        sanitized: false,
        auth_gated: hit.authGated,
        auth_gates: hit.authGates,
        interprocedural: true,
        via_return: item.viaReturn,
      });
    }

    for (const c of sum.paramCalls.get(item.param) ?? []) {
      const calleeId = resolveFuncId(c.callee, summaries);
      if (!calleeId) continue;
      const calleeParam = summaries.get(calleeId)!.params[c.argIndex];
      if (calleeParam) queue.push({ funcId: calleeId, param: calleeParam, source: item.source, sourceLine: item.sourceLine, viaReturn: false });
    }
  }

  // Emit function-internal source→sink flows (framework controllers read user
  // input inside the body, not via a tainted argument).
  const seenInternal = new Set<string>();
  for (const sum of summaries.values()) {
    for (const hit of sum.internalSinks) {
      const cls = classifySink(hit.sink);
      if (!cls) continue;
      const key = `${hit.sink}:${hit.line}`;
      if (seenInternal.has(key)) continue;
      seenInternal.add(key);
      if (hit.sanitized) {
        result.suppressed += 1;
        continue;
      }
      result.findings.push({
        sink: hit.sink,
        sink_line: hit.line,
        category: cls.category,
        cwe: cls.cwe,
        sanitized: false,
        auth_gated: hit.authGated,
        auth_gates: hit.authGates,
        interprocedural: false,
        via_return: false,
        internal_source: true,
      });
    }
  }

  if (cacheCode) setCache("eagle2", cacheCode, result);
  return result;
}
