/** Cross-file privilege-escalation detection (reverse call-graph trace).
 *
 *  The per-file authz detector only sees a handler and its own body. Real
 *  privilege-escalation bugs are CROSS-FILE: a public entry point (registration
 *  hook, `wp_ajax_nopriv_*`, `init`/`template_redirect`) in one file calls into a
 *  setter method in another file that performs a privileged sink fed by request
 *  input — e.g. a plugin's `set_role($user_id, sanitize_key($_POST['role']))`.
 *
 *  This module builds a lightweight call graph (function/method name → body →
 *  callees) and REVERSE-traces from a privileged sink up to a public entry point.
 *  A finding fires only when: (1) the sink is directly fed by request input,
 *  (2) it is reachable from a PUBLIC (unauthenticated) entry, and (3) no
 *  capability check appears anywhere along the caller chain.
 */
import type { ComplexFinding } from "./complex-bugs.js";
import { iterSourceFiles, stripComments } from "./scanner.js";
import { readFileSync } from "node:fs";

/** Hooks that fire for UNAUTHENTICATED visitors — the real attack surface. */
const PUBLIC_HOOK_RE = /(?:wp_ajax_nopriv_\w+|admin_post_nopriv_\w+|init|template_redirect|wp_loaded|parse_request|user_register|um_user_register|register_new_user|authenticate)/;

/** Privileged sinks: grant a role/capability or set the current user. */
const PRIV_SINK_RE = /\b(set_role|add_role|remove_role|set_user_role|wp_set_current_user|wp_set_auth_cookie|wp_insert_user|wp_create_user|wp_update_user)\s*\(/;
/** update_user_meta with a role/capability key (the other priv-esc shape). */
const ROLE_META_RE = /update_user_meta\s*\(\s*[^,]+,\s*['"](wp_capabilities|role|roles|capabilities|wp_user_level)['"]/;

const SOURCE_RE = /\$_(GET|POST|REQUEST|COOKIE|FILES)\b|php:\/\/input|->(input|query|request)\(/;
const CAP_RE = /\b(current_user_can|is_user_logged_in|is_super_admin|check_ajax_referer|check_admin_referer|wp_verify_nonce|authorize|user_can)\s*\(/;

interface FnEntry {
  name: string;
  file: string;
  line: number;
  body: string;
  callees: string[]; // function/method names called by this body
}

/** Extract the body of `function name(` (works for top-level functions AND
 *  class methods, since both use `function name(...) { ... }`). */
function fnBody(code: string, name: string): string | null {
  const re = new RegExp(`function\\s+${name}\\s*\\(`);
  const idx = code.search(re);
  if (idx === -1) return null;
  const open = code.indexOf("{", idx);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") {
      depth--;
      if (depth === 0) return code.slice(open + 1, i);
    }
  }
  return null;
}

/** Extract every function/method name this body calls (foo( / ->foo( / ::foo(). */
function extractCallees(body: string): string[] {
  const names = new Set<string>();
  const re = /(?:\$[\w\\]+\s*->|\$this\s*->|\b[\w\\]+\s*::)?([A-Za-z_]\w*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const name = m[1];
    if (name.length > 1) names.add(name);
  }
  return [...names];
}

function lineNo(code: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

/** Build the cross-file call graph + reverse-trace privileged sinks to public
 *  entry points. */
export function detectCrossFilePrivesc(root: string): ComplexFinding[] {
  const files = iterSourceFiles(root);
  const out: ComplexFinding[] = [];

  // --- Pass 0: DIRECT privilege escalation — a privileged sink whose ARGUMENTS
  // are themselves request input (e.g. set_role($id, sanitize_key($_POST['um-role']))).
  // This is the most precise signal: the role/capability value is user-controlled. ---
  const directSinkRe = /\b(set_role|add_role|remove_role|set_user_role|wp_set_current_user|wp_set_auth_cookie|wp_insert_user|wp_create_user|wp_update_user)\s*\(\s*([^;]*?)\)/g;
  const metaSinkRe = /update_user_meta\s*\(\s*[^,]+,\s*['"](wp_capabilities|role|roles|capabilities|wp_user_level)['"]\s*,\s*([^;]*?)\)/g;
  for (const file of files) {
    let code: string;
    try {
      code = stripComments(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    let m: RegExpExecArray | null;
    directSinkRe.lastIndex = 0;
    while ((m = directSinkRe.exec(code)) !== null) {
      const fnName = m[1];
      const args = m[2];
      if (!SOURCE_RE.test(args)) continue;
      out.push({
        file, line: lineNo(code, m.index), type: "priv_esc",
        category: "Privilege escalation (role/user set from request input)",
        severity: "high",
        evidence: `${fnName}(${args.trim().slice(0, 80)})`,
        detail: `'${fnName}()' sets a role/capability/user directly from request input without a whitelist — unauthenticated privilege escalation.`,
      });
    }
    metaSinkRe.lastIndex = 0;
    while ((m = metaSinkRe.exec(code)) !== null) {
      const value = m[2];
      if (!SOURCE_RE.test(value)) continue;
      out.push({
        file, line: lineNo(code, m.index), type: "priv_esc",
        category: "Privilege escalation (role/capability meta set from request input)",
        severity: "high",
        evidence: `update_user_meta(..., '${m[1]}', ${value.trim().slice(0, 60)})`,
        detail: `update_user_meta sets '${m[1]}' (a role/capability key) from request input — unauthenticated privilege escalation.`,
      });
    }
  }

  // 1. Index every function/method by name (collapsed namespace — acceptable
  //    for a triage lead; collisions are rare within a single plugin).
  const fns = new Map<string, FnEntry>();
  for (const file of files) {
    let code: string;
    try {
      code = stripComments(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    const re = /function\s+(&?[A-Za-z_]\w*)\s*\(/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const name = m[1].replace(/^&/, "");
      if (name === "__construct" || name === "__destruct" || name === "__call" || name === "__get" || name === "__set") continue;
      if (fns.has(name)) continue; // first definition wins
      const body = fnBody(code, name);
      if (!body) continue;
      fns.set(name, { name, file, line: lineNo(code, m.index), body, callees: extractCallees(body) });
    }
  }

  // 2. Identify public entry functions (registered to an unauth hook) and
  //    privileged sink functions (sink fed by request input).
  const entries = new Map<string, FnEntry>(); // hook -> entry fn
  const entryFiles = new Set<string>();
  for (const file of files) {
    let code: string;
    try {
      code = stripComments(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    // add_action('hook', 'handler') / add_action('hook', array($this,'handler'))
    const hookRe = /add_action\s*\(\s*['"]([^'"]+)['"]\s*,\s*(['"][\w]+['"]|array\s*\(\s*[^,]+,\s*['"][\w]+['"]\s*\))/g;
    let m: RegExpExecArray | null;
    while ((m = hookRe.exec(code)) !== null) {
      const hook = m[1];
      if (!PUBLIC_HOOK_RE.test(hook)) continue;
      const nameMatch = m[2].match(/['"]([A-Za-z_]\w*)['"]/g);
      const name = nameMatch ? nameMatch[nameMatch.length - 1].replace(/['"]/g, "") : null;
      if (!name) continue;
      const entry = fns.get(name);
      if (!entry) continue;
      entries.set(`${file}:${name}`, entry);
      entryFiles.add(file);
    }
  }

  // 3. Reverse-trace: callee -> callers.
  const callers = new Map<string, FnEntry[]>(); // callee name -> callers
  for (const fn of fns.values()) {
    for (const callee of fn.callees) {
      const arr = callers.get(callee) ?? [];
      arr.push(fn);
      callers.set(callee, arr);
    }
  }

  // 4. Find privileged sinks fed by request input, then BFS up to a public entry.
  const sinkFunctions: FnEntry[] = [];
  for (const fn of fns.values()) {
    const isPriv = PRIV_SINK_RE.test(fn.body) || ROLE_META_RE.test(fn.body);
    const hasSource = SOURCE_RE.test(fn.body);
    if (isPriv && hasSource) sinkFunctions.push(fn);
  }

  for (const sink of sinkFunctions) {
    // BFS up the caller chain, bounded depth, tracking capability checks.
    const seen = new Set<string>([sink.name]);
    let queue: Array<{ fn: FnEntry; hasCap: boolean }> = [{ fn: sink, hasCap: CAP_RE.test(sink.body) }];
    let reachedPublic = false;
    let publicEntry: FnEntry | null = null;
    const chainCap = new Map<string, boolean>([[sink.name, CAP_RE.test(sink.body)]]);

    while (queue.length > 0) {
      const next: Array<{ fn: FnEntry; hasCap: boolean }> = [];
      for (const { fn, hasCap } of queue) {
        // Is this function itself a public entry?
        if (fn.file && entryFiles.has(fn.file)) {
          // check if fn is directly registered as a public handler
          for (const [, e] of entries) {
            if (e.name === fn.name) {
              reachedPublic = true;
              publicEntry = e;
            }
          }
        }
        const up = callers.get(fn.name) ?? [];
        for (const caller of up) {
          if (seen.has(caller.name)) continue;
          seen.add(caller.name);
          const cap = hasCap || CAP_RE.test(caller.body);
          chainCap.set(caller.name, cap);
          // If the caller IS a public entry → reached.
          for (const [, e] of entries) {
            if (e.name === caller.name) {
              reachedPublic = true;
              publicEntry = e;
              chainCap.set(caller.name, cap);
            }
          }
          next.push({ fn: caller, hasCap: cap });
          if (next.length > 500) break;
        }
        if (reachedPublic) break;
      }
      if (reachedPublic) break;
      queue = next;
      if (seen.size > 2000) break;
    }

    if (!reachedPublic || !publicEntry) continue;
    const capFound = [...seen].some((n) => chainCap.get(n));
    if (capFound) continue; // a capability check protects the chain

    out.push({
      file: sink.file,
      line: sink.line,
      type: "priv_esc",
      category: "Privilege escalation (privileged sink reachable from public entry)",
      severity: "high",
      evidence: `${sink.name}() — reachable from public hook '${publicEntry.name}'`,
      detail: `'${sink.name}()' in ${sink.file} performs a privileged operation (role/capability/user change) fed by request input, and is reachable from the public entry '${publicEntry.name}' (${publicEntry.file}) with no capability check on the chain — unauth privilege escalation.`,
    });
  }

  // Dedup by (file, line).
  const seen = new Set<string>();
  return out.filter((f) => {
    const k = `${f.file}:${f.line}:${f.type}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
