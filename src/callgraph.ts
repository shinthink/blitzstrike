/** Call graph (§ "EAGLE-EYE 2.0") — function/method call resolution on a PHP AST.
 *
 * Builds a sound (over-approximate) call graph: function calls resolve by name,
 * `$this->m()` resolves to the enclosing class's method, and `$obj->m()` /
 * static calls use Class Hierarchy Analysis (CHA) — every method named `m` is a
 * potential callee. This is the foundation for whole-program interprocedural
 * taint (return propagation + worklist) in `eagle2.ts`.
 */
import { readFileSync } from "node:fs";
import { Engine } from "php-parser";
import type { AstNode } from "./ast.js";

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

/** Resolve an identifier node's name (php-parser wraps names in identifier nodes). */
function nameOf(node: unknown): string | null {
  if (!isNode(node)) return null;
  if (typeof node.name === "string") return node.name;
  if (isNode(node.name)) return nameOf(node.name);
  return null;
}

export type CallGraphNodeKind = "function" | "method" | "main";

export interface CallGraphNode {
  id: string;
  name: string;
  kind: CallGraphNodeKind;
  class?: string;
  file: string;
  line: number;
  callees: Set<string>;
  callers: Set<string>;
}

export interface CallEdge {
  caller: string;
  callee: string;
  /** callee name as written in source (for unresolved edges) */
  name: string;
  line: number;
  file: string;
}

export interface CallGraph {
  nodes: Map<string, CallGraphNode>;
  edges: CallEdge[];
}

function nodeId(kind: CallGraphNodeKind, name: string, cls?: string): string {
  if (kind === "function") return `func:${name}`;
  if (kind === "method") return `method:${cls ?? "?"}::${name}`;
  return "main";
}

function ensureNode(g: CallGraph, id: string, name: string, kind: CallGraphNodeKind, file: string, line: number, cls?: string): CallGraphNode {
  let n = g.nodes.get(id);
  if (!n) {
    n = { id, name, kind, class: cls, file, line, callees: new Set(), callers: new Set() };
    g.nodes.set(id, n);
  }
  return n;
}

function addEdge(g: CallGraph, caller: string, callee: string, name: string, line: number, file: string): void {
  g.edges.push({ caller, callee, name, line, file });
  const c = g.nodes.get(caller);
  const t = g.nodes.get(callee);
  if (c) c.callees.add(callee);
  if (t) t.callers.add(caller);
}

/** Build a call graph for a single PHP file. */
export function buildCallGraph(path: string): CallGraph {
  const g: CallGraph = { nodes: new Map(), edges: [] };
  let code: string;
  try {
    code = readFileSync(path, "utf8");
  } catch {
    return g;
  }
  let ast: Node;
  try {
    ast = parser.parseCode(code, path) as Node;
  } catch {
    return g;
  }

  const mainId = nodeId("main", "main");
  ensureNode(g, mainId, "<main>", "main", path, 0);

  // First pass: collect all function + method declarations (so edges resolve).
  const funcs: Array<{ name: string; node: Node }> = [];
  const methods: Array<{ cls: string; name: string; node: Node }> = [];
  walk(ast, path, (n, ctx) => {
    if (n.kind === "function") {
      const name = nameOf(n.name);
      if (name) funcs.push({ name, node: n });
    } else if (n.kind === "method" && ctx.className) {
      const mname = nameOf(n.name);
      if (mname) methods.push({ cls: ctx.className, name: mname, node: n });
    }
  });

  for (const f of funcs) {
    const id = nodeId("function", f.name);
    ensureNode(g, id, f.name, "function", path, f.node.loc?.start?.line ?? 0);
  }
  for (const m of methods) {
    const id = nodeId("method", m.name, m.cls);
    ensureNode(g, id, m.name, "method", path, m.node.loc?.start?.line ?? 0, m.cls);
  }

  // Second pass: resolve call edges with enclosing-function context.
  walk(ast, path, (n, ctx) => {
    if (n.kind !== "call") return;
    const line = n.loc?.start?.line ?? 0;
    const callerId = ctx.enclosing ?? mainId;
    resolveCall(g, n, callerId, ctx, path, line);
  });

  return g;
}

interface WalkCtx {
  className?: string;
  enclosing?: string; // enclosing function/method node id
}

function walk(node: Node, file: string, visit: (n: Node, ctx: WalkCtx) => void, ctx: WalkCtx = {}): void {
  if (!isNode(node)) return;
  // Compute child context before visiting children.
  let childCtx = ctx;
  if (node.kind === "class") {
    childCtx = { ...ctx, className: nameOf(node.name) ?? undefined };
  } else if (node.kind === "function") {
    const name = nameOf(node.name);
    childCtx = { ...ctx, enclosing: name ? nodeId("function", name) : ctx.enclosing };
  } else if (node.kind === "method") {
    const name = nameOf(node.name);
    childCtx = { ...ctx, enclosing: name ? nodeId("method", name, ctx.className) : ctx.enclosing };
  }

  visit(node, ctx);

  for (const c of children(node)) walk(c, file, visit, childCtx);
}

function resolveCall(g: CallGraph, call: Node, callerId: string, ctx: WalkCtx, file: string, line: number): void {
  const what = call.what;
  if (!isNode(what)) return;

  // function call: name(...)
  if (what.kind === "name") {
    const fn = nameOf(what);
    if (!fn) return;
    const id = nodeId("function", fn);
    if (g.nodes.has(id)) {
      addEdge(g, callerId, id, fn, line, file);
    } else {
      addEdge(g, callerId, `unknown:${fn}`, fn, line, file);
    }
    return;
  }

  // static call: Class::method(...) or self::method(...) / static::method(...)
  if (what.kind === "staticlookup") {
    const base = what.what;
    const baseName = nameOf(base) ?? (isNode(base) && base.kind === "variable" ? base.name : null);
    const method = nameOf(what.offset);
    if (!method) return;
    let cls = baseName;
    if (cls === "self" || cls === "static") cls = ctx.className ?? "?";
    if (cls && cls !== "?") {
      const id = nodeId("method", method, cls);
      if (g.nodes.has(id)) addEdge(g, callerId, id, method, line, file);
    }
    return;
  }

  // method call: $base->method(...)
  if (what.kind === "propertylookup") {
    const base = what.what;
    const method = nameOf(what.offset);
    if (!method) return;
    // $this->m() resolves to the enclosing class.
    if (isNode(base) && base.kind === "variable" && base.name === "this") {
      if (ctx.className) {
        const id = nodeId("method", method, ctx.className);
        if (g.nodes.has(id)) addEdge(g, callerId, id, method, line, file);
      }
      return;
    }
    // Any other receiver -> CHA: every method with that name is a candidate.
    let matched = false;
    for (const [id, n] of g.nodes) {
      if (n.kind === "method" && n.name === method) {
        addEdge(g, callerId, id, method, line, file);
        matched = true;
      }
    }
    if (!matched) addEdge(g, callerId, `unknown:${method}`, method, line, file);
    return;
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/** Set of functions/methods reachable (transitively) from an entry node. */
export function reachableFrom(g: CallGraph, entry: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entry];
  while (stack.length) {
    const cur = stack.pop()!;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const n = g.nodes.get(cur);
    if (!n) continue;
    for (const c of n.callees) stack.push(c);
  }
  return seen;
}

/** Nodes with no callers (entry points: uncalled helpers + main). */
export function entryPoints(g: CallGraph): string[] {
  const entries: string[] = [];
  for (const [id, n] of g.nodes) {
    if (n.callers.size === 0) entries.push(id);
  }
  return entries;
}
