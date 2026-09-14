/** BLITZ + EAGLE-EYE scanning engine (TypeScript/Bun).
 *
 * Port of the Python scanner. Zero third-party runtime deps — uses node:fs
 * + node:path only, so the toolbelt works in any environment.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Pattern tables (PHP-focused; the highest-yield bug-hunting surface)
// ---------------------------------------------------------------------------

export const NOPRIV_HOOKS = [
  "wp_ajax_nopriv_",
  "admin_post_nopriv_",
  "register_rest_route", // REST routes: permission_callback determines auth
  "wp_ajax_", // admin-only but worth flagging with the gate note
];

export const SINKS: Record<string, string> = {
  "eval(": "RCE (code execution)",
  "assert(": "RCE (code execution, PHP <8)",
  "system(": "RCE (command execution)",
  "shell_exec(": "RCE (command execution)",
  "passthru(": "RCE (command execution)",
  "proc_open(": "RCE (command execution)",
  "popen(": "RCE (command execution)",
  "move_uploaded_file(": "File upload (-> RCE if .php lands in webroot)",
  "file_put_contents(": "Arbitrary file write (-> RCE via CF-003)",
  "fwrite(": "Arbitrary file write",
  "unserialize(": "PHP object injection (POP gadget chain)",
  "maybe_unserialize(": "PHP object injection (weak)",
  "include(": "Local file inclusion",
  "require(": "Local file inclusion",
  "include_once(": "Local file inclusion",
  "require_once(": "Local file inclusion",
  "$wpdb->query(": "SQL injection (unprepared query)",
  "$wpdb->get_var(": "SQL injection (unprepared query)",
  "$wpdb->get_results(": "SQL injection (unprepared query)",
  "->query(": "SQL injection (query builder)",
  "->whereRaw(": "SQL injection (raw where)",
  "->selectRaw(": "SQL injection (raw select)",
  "DB::select(": "SQL injection (raw query)",
  "DB::raw(": "SQL injection (raw expression)",
  "DB::statement(": "SQL injection (raw statement)",
  "DB::insert(": "SQL injection (raw insert)",
  "DB::update(": "SQL injection (raw update)",
  "DB::unprepared(": "SQL injection (raw unprepared query)",
  "wp_remote_get(": "SSRF (unvalidated URL fetch)",
  "wp_remote_post(": "SSRF (unvalidated URL fetch)",
  "file_get_contents(": "SSRF / file read",
  "extract(": "Variable injection (-> LFI/RCE without EXTR_SKIP)",
  "call_user_func(": "Dynamic dispatch (attacker-controlled callback)",
  "call_user_func_array(": "Dynamic dispatch",
  "create_function(": "RCE (deprecated eval wrapper)",
  "preg_replace(": "RCE (if /e modifier or code in pattern)",
  "echo ": "XSS (reflected output)",
  "print ": "XSS (reflected output)",
  "printf(": "XSS (reflected output)",
  "header(": "Open redirect / header injection",
  "wp_redirect(": "Open redirect",
  // --- Node.js ---
  "child_process.exec(": "RCE (command execution)",
  "child_process.spawn(": "RCE (command execution)",
  "child_process.execSync(": "RCE (command execution)",
  "child_process.execFile(": "RCE (command execution)",
  "sqlx::query(&format!": "SQL injection (runtime string-built query)",
  "sqlx::query_as(&format!": "SQL injection (runtime string-built query)",
  "sequelize.query(": "SQL injection (raw query)",
  "knex.raw(": "SQL injection (raw query)",
  // --- Python ---
  "subprocess.run(": "RCE (command execution)",
  "subprocess.call(": "RCE (command execution)",
  "subprocess.Popen(": "RCE (command execution)",
  "subprocess.check_output(": "RCE (command execution)",
  "os.system(": "RCE (command execution)",
  "os.popen(": "RCE (command execution)",
  "requests.get(": "SSRF (unvalidated URL fetch)",
  "requests.post(": "SSRF (unvalidated URL fetch)",
  "requests.put(": "SSRF (unvalidated URL fetch)",
  "urllib.request.urlopen(": "SSRF (unvalidated URL fetch)",
  "urllib.urlopen(": "SSRF (unvalidated URL fetch)",
  "httpx.get(": "SSRF (unvalidated URL fetch)",
  "render_template_string(": "SSTI (server-side template injection)",
  "jinja2.Template(": "SSTI (server-side template injection)",
  "Template(": "SSTI (server-side template injection)",
};

export const AUTH_GATES = [
  "check_ajax_referer",
  "check_admin_referer",
  "wp_verify_nonce",
  "current_user_can",
  "is_user_logged_in",
  "JSession::checkToken",
  "->authorise(",
  "->authorize(",
  "permission_callback",
];

const TARGET_EXTS = new Set([
  ".php",
  ".phtml",
  ".php5",
  ".php7",
  ".inc",
  ".module",
  ".install",
  ".py",
  ".pyw",
  ".java",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  // more languages
  ".rb",
  ".go",
  ".rs",
  ".cs",
  ".c",
  ".h",
  ".cpp",
  ".cc",
  ".hpp",
  ".sh",
  ".bash",
  ".sol",
  // config / manifests (cache_deception, dependency_confusion, oauth/grpc, etc.)
  ".conf",
  ".config",
  ".nginx",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".xml",
  ".properties",
  ".gradle",
  ".proto",
  ".env",
  ".txt",
]);

const SKIP_PARTS = new Set(["vendor", "node_modules", ".git", "tests", "test"]);
// Only genuinely-third-party dirs are skipped. `lib` / `libraries` / `libs` are
// NOT skipped: many plugins (a migration plugin, a file-manager's bundled library)
// keep their OWN code under `lib/`, and skipping it silently MISSES the whole
// plugin (a false-negative worse than any false positive).
const LIB_PARTS = new Set([
  "third-party",
  "third_party",
]);

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function lineno(text: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) {
    if (text.charCodeAt(i) === 10) n++;
  }
  return n;
}

/** Replace comments (//, #, /* … *​/) AND string literals ('…' / "…") with spaces,
 *  preserving character positions and line numbers so `lineno` stays accurate.
 *  A sink token inside a comment or string is not a real function call, so the
 *  breadth scanner must not report it. */
export function stripComments(text: string): string {
  const out = text.split("");
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    const nc = text[i + 1];
    if (c === "'" || c === '"') {
      const q = c;
      out[i] = " ";
      i++;
      while (i < n && text[i] !== q) {
        if (text[i] === "\\") {
          out[i] = " ";
          i++;
          if (i < n) out[i] = " ";
          i++;
          continue;
        }
        if (text[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) out[i] = " "; // closing quote
      i++;
      continue;
    }
    if ((c === "/" && nc === "/") || c === "#") {
      while (i < n && text[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }
    if (c === "/" && nc === "*") {
      out[i] = " ";
      out[i + 1] = " ";
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) {
        if (text[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) {
        out[i] = " ";
        out[i + 1] = " ";
        i += 2;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

export interface EndpointHit {
  hook: string;
  line: number;
}

export interface SinkHit {
  sink: string;
  class: string;
  line: number;
}

export interface ScanResult {
  file: string;
  lines?: number;
  error?: string;
  endpoints: EndpointHit[];
  sinks: SinkHit[];
  auth_gates_present: string[];
}

/** Recursively collect source files, skipping vendor/test/lib dirs. */
export function iterSourceFiles(root: string, maxFiles = 5000): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    if (out.length >= maxFiles) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (out.length >= maxFiles) return;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (SKIP_PARTS.has(name) || LIB_PARTS.has(name)) continue;
        walk(full);
      } else if (st.isFile()) {
        const dot = name.lastIndexOf(".");
        const ext = dot >= 0 ? name.slice(dot).toLowerCase() : "";
        if (!TARGET_EXTS.has(ext)) continue;
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

function findFunctionBounds(text: string, funcStart: number): [number, number] | null {
  const brace = text.indexOf("{", funcStart);
  if (brace === -1) return null;
  let depth = 0;
  for (let i = brace; i < text.length; i++) {
    const c = text[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return [funcStart, i + 1];
    }
  }
  return null;
}

export function scanFile(path: string): ScanResult {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { file: path, endpoints: [], sinks: [], auth_gates_present: [], error: "unreadable" };
  }

  // Match sinks/hooks against comment-stripped source so a sink token inside a
  // comment (e.g. "// use extract($_REQUEST)") is not reported as a hit.
  const code = stripComments(text);

  const endpoints: EndpointHit[] = [];
  for (const hook of NOPRIV_HOOKS) {
    const re = new RegExp(escapeRegExp(hook), "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      endpoints.push({ hook, line: lineno(code, m.index) });
    }
  }

  const sinks: SinkHit[] = [];
  for (const [sink, bugclass] of Object.entries(SINKS)) {
    const re = new RegExp(escapeRegExp(sink), "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      sinks.push({ sink, class: bugclass, line: lineno(code, m.index) });
    }
  }

  const gates = AUTH_GATES.filter((g) => code.includes(g));
  const lines = text.split("\n").length;

  return { file: path, lines, endpoints, sinks, auth_gates_present: gates };
}

export interface FunctionDef {
  line: number;
  line_end: number;
  length: number;
  sinks_in_scope: SinkHit[];
  auth_gates_in_scope: string[];
  body_preview: string;
}

export interface TraceResult {
  file: string;
  symbol: string;
  error?: string;
  definitions: FunctionDef[];
  definition_count: number;
}

export function traceFunction(path: string, symbol: string): TraceResult {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { file: path, symbol, definitions: [], definition_count: 0, error: "unreadable" };
  }

  const pattern = new RegExp(`function\\s+&?${escapeRegExp(symbol)}\\s*\\(`, "g");
  const results: FunctionDef[] = [];
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    const bounds = findFunctionBounds(text, m.index);
    if (!bounds) continue;
    const [start, end] = bounds;
    const body = text.slice(start, end);
    const bodyCode = stripComments(body);
    const bodyStartLine = lineno(text, start);
    const bodyEndLine = lineno(text, end);

    const innerSinks: SinkHit[] = [];
    for (const [sink, bugclass] of Object.entries(SINKS)) {
      const re = new RegExp(escapeRegExp(sink), "g");
      let sm: RegExpExecArray | null;
      while ((sm = re.exec(bodyCode)) !== null) {
        innerSinks.push({
          sink,
          class: bugclass,
          line: bodyStartLine + bodyCode.slice(0, sm.index).split("\n").length - 1,
        });
      }
    }

    const innerGates = AUTH_GATES.filter((g) => bodyCode.includes(g));

    results.push({
      line: bodyStartLine,
      line_end: bodyEndLine,
      length: end - start,
      sinks_in_scope: innerSinks,
      auth_gates_in_scope: innerGates,
      body_preview: body.slice(0, 4000),
    });
  }

  return {
    file: path,
    symbol,
    definitions: results,
    definition_count: results.length,
  };
}

export interface GrepHit {
  file: string;
  line: number;
  sink: string;
  auth_gates_in_scope: string[];
  guarded: boolean;
}

export function grepInFunctions(root: string, sink: string, maxHits = 50): GrepHit[] {
  const hits: GrepHit[] = [];
  for (const p of iterSourceFiles(root)) {
    if (hits.length >= maxHits) break;
    let text: string;
    try {
      text = readFileSync(p, "utf8");
    } catch {
      continue;
    }
    const code = stripComments(text);
    const re = new RegExp(escapeRegExp(sink), "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const line = lineno(code, m.index);
      const head = code.slice(0, m.index);
      const funcRe = /function\s+&?\w+\s*\(/g;
      const funcs: RegExpExecArray[] = [];
      let fm: RegExpExecArray | null;
      while ((fm = funcRe.exec(head)) !== null) funcs.push(fm);
      if (funcs.length === 0) continue;
      const fstart = funcs[funcs.length - 1].index;
      const bounds = findFunctionBounds(code, fstart);
      if (!bounds || !(bounds[0] <= m.index && m.index < bounds[1])) continue;
      const body = code.slice(bounds[0], bounds[1]);
      const gates = AUTH_GATES.filter((g) => body.includes(g));
      hits.push({
        file: p,
        line,
        sink,
        auth_gates_in_scope: gates,
        guarded: gates.length > 0,
      });
      if (hits.length >= maxHits) break;
    }
  }
  return hits;
}
