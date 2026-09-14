/** Language adapters — thin per-language parsers that emit the generic IR.
 *
 * Each adapter parses a source language into SOURCE/SINK/SANITIZE/CALL/ASSIGN
 * events consumed by the language-agnostic taint engine (universal-taint.ts).
 *
 * Parser choices (all pure-JS, no native bindings, license-compliant):
 *   php        — php-parser (BSD-3-Clause)
 *   javascript — @babel/parser (MIT)
 *   python     — @lezer/python (MIT)
 *   java       — java-parser (Apache-2.0)
 */
import { registerLanguage, type LanguageAdapter, type SinkKind, type SourceKind, type IrSource, type IrSink, type IrSanitize, type IrCall, type IrAssign } from "./universal-taint.js";
import { Engine } from "php-parser";
import type { AstNode } from "./ast.js";
import { parse as babelParse } from "@babel/parser";
import { parser as pythonParser } from "@lezer/python";

// ---------------------------------------------------------------------------
// PHP adapter (php-parser)
// ---------------------------------------------------------------------------

const phpEngine = new Engine({ parser: { extractDoc: false, php7: true }, ast: { withPositions: true, withSource: false } });

const PHP_SOURCES: Array<[string, SourceKind]> = [
  ["_GET", "http_parameter"], ["_POST", "http_body"], ["_REQUEST", "http_parameter"],
  ["_COOKIE", "http_cookie"], ["_FILES", "uploaded_file"], ["_SERVER", "http_header"],
];
const PHP_SINKS: Array<[string, SinkKind, string?]> = [
  ["query", "sql_execution", "CWE-89"], ["whereRaw", "sql_execution", "CWE-89"],
  ["system", "command_execution", "CWE-78"], ["exec", "command_execution", "CWE-78"],
  ["shell_exec", "command_execution", "CWE-78"], ["eval", "code_execution", "CWE-94"],
  ["unserialize", "deserialization", "CWE-502"], ["move_uploaded_file", "file_operations", "CWE-434"],
  ["file_put_contents", "file_operations", "CWE-434"], ["include", "file_inclusion", "CWE-98"],
  ["require", "file_inclusion", "CWE-98"], ["file_get_contents", "http_request", "CWE-918"],
  ["simplexml_load_string", "xml_processing", "CWE-611"], ["simplexml_load_file", "xml_processing", "CWE-611"],
  ["extractTo", "archive_extraction", "CWE-22"],
  ["createTemplate", "template_injection", "CWE-1336"], ["xpath", "xpath_injection", "CWE-643"],
  ["ldap_search", "ldap_injection", "CWE-90"], ["ldap_list", "ldap_injection", "CWE-90"], ["ldap_read", "ldap_injection", "CWE-90"],
];
const PHP_SANITIZERS: Array<[string, SinkKind[]]> = [
  ["htmlspecialchars", ["html_render"]], ["esc_html", ["html_render"]], ["htmlentities", ["html_render"]],
  ["esc_sql", ["sql_execution"]], ["prepare", ["sql_execution"]], ["intval", ["sql_execution", "command_execution", "file_inclusion"]],
  ["escapeshellarg", ["command_execution"]], ["filter_var", ["html_render", "sql_execution", "command_execution"]],
];

function phpVar(node: AstNode): string | null {
  if (!node || typeof node !== "object") return null;
  if (node.kind === "variable") return node.name ?? null;
  if (node.kind === "offsetlookup" || node.kind === "propertylookup") return phpVar(node.what);
  return null;
}

function phpWalk(node: AstNode, out: AstNode[]): AstNode[] {
  if (!node || typeof node !== "object") return out;
  out.push(node);
  for (const k of Object.keys(node)) {
    if (k === "loc") continue;
    const v = node[k];
    if (Array.isArray(v)) for (const c of v) phpWalk(c, out);
    else if (v && typeof v === "object" && v.kind) phpWalk(v, out);
  }
  return out;
}

const phpAdapter: LanguageAdapter = {
  language: "php",
  extensions: [".php", ".phtml", ".php5", ".php7", ".inc", ".module", ".install"],
  parse(code, file) {
    const ast = phpEngine.parseCode(code, file);
    const nodes = phpWalk(ast, []);
    const sources: IrSource[] = [];
    const sinks: IrSink[] = [];
    const sanitizers: IrSanitize[] = [];
    const calls: IrCall[] = [];
    const assigns: IrAssign[] = [];

    for (const n of nodes) {
      // source: $_GET['x'] (offsetlookup on superglobal)
      if (n.kind === "offsetlookup" && n.what?.kind === "variable") {
        const sup = PHP_SOURCES.find(([t]) => t === n.what.name);
        if (sup) {
          sources.push({ variable: "superglobal:" + sup[0], kind: sup[1], line: n.loc?.start?.line ?? 0, attacker_controlled: true });
        }
      }
      // assign: $x = <right>
      if (n.kind === "assign") {
        const target = phpVar(n.left);
        const rhsVars: string[] = [];
        for (const c of phpWalk(n.right, [])) if (c.kind === "variable" && c.name) rhsVars.push(c.name);
        if (target) assigns.push({ target, sources: rhsVars, line: n.loc?.start?.line ?? 0 });
      }
      // call (sink / sanitizer / helper)
      if (n.kind === "call") {
        const what = n.what;
        let callee = "";
        if (what?.kind === "propertylookup") callee = what.offset?.name ?? what.offset?.value ?? "";
        else if (what?.kind === "name") callee = what.name ?? "";
        if (callee) {
          const argVars: string[] = [];
          for (const c of phpWalk(n, [])) if (c.kind === "variable" && !["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].includes(c.name)) argVars.push(c.name);
          // sink
          const sink = PHP_SINKS.find(([t]) => callee === t || callee.includes(t));
          if (sink) {
            for (const v of argVars) sinks.push({ variable: v, kind: sink[1], line: n.loc?.start?.line ?? 0, cwe: sink[2] });
          }
          // sanitizer
          const san = PHP_SANITIZERS.find(([t]) => callee === t || callee.includes(t));
          if (san) {
            for (const v of argVars) sanitizers.push({ variable: v, neutralizes: san[1], line: n.loc?.start?.line ?? 0 });
          }
          calls.push({ name: callee, args: argVars, line: n.loc?.start?.line ?? 0 });
        }
      }
    }

    // map superglobal sources to assigned variables: $id = $_GET[...]
    // (handled by the generic engine's assign propagation, but we need to link
    // superglobal:GET taint to the assigned variable.) Simplest: emit source on
    // the assignment target when RHS contains a superglobal.
    for (const n of nodes) {
      if (n.kind === "assign") {
        const target = phpVar(n.left);
        const rhs = phpWalk(n.right, []);
        for (const c of rhs) {
          if (c.kind === "offsetlookup" && c.what?.kind === "variable") {
            const sup = PHP_SOURCES.find(([t]) => t === c.what.name);
            if (sup && target) sources.push({ variable: target, kind: sup[1], line: n.loc?.start?.line ?? 0, attacker_controlled: true });
          }
        }
      }
    }

    return { sources, sinks, sanitizers, calls, assigns };
  },
};

// ---------------------------------------------------------------------------
// JavaScript / TypeScript adapter (@babel/parser)
// ---------------------------------------------------------------------------

const JS_SOURCES: Array<[RegExp, SourceKind]> = [
  [/req\.query/i, "http_parameter"], [/req\.body/i, "http_body"], [/req\.params/i, "http_parameter"],
  [/req\.headers/i, "http_header"], [/req\.cookies/i, "http_cookie"], [/request\.get/i, "http_parameter"],
  [/req\.getParameter/i, "http_parameter"], [/req\.getHeader/i, "http_header"],
];
const JS_SINKS: Array<[RegExp, SinkKind, string?]> = [
  [/\.query\s*\(/i, "sql_execution", "CWE-89"], [/eval\s*\(/i, "code_execution", "CWE-94"],
  [/exec\s*\(/i, "command_execution", "CWE-78"], [/execSync\s*\(/i, "command_execution", "CWE-78"],
  [/\.send\s*\(/i, "html_render", "CWE-79"],
  [/innerHTML/i, "html_render", "CWE-79"], [/document\.write/i, "html_render", "CWE-79"],
  [/fs\.writeFile/i, "file_operations", "CWE-434"], [/fs\.appendFile/i, "file_operations", "CWE-434"],
  [/fs\.readFile/i, "path_traversal", "CWE-22"], [/fs\.readFileSync/i, "path_traversal", "CWE-22"],
  [/fs\.unlink/i, "file_operations", "CWE-434"],
  [/fetch\s*\(/i, "http_request", "CWE-918"], [/http\.get|https\.get|axios/i, "http_request", "CWE-918"],
  [/http\.request|https\.request/i, "http_request", "CWE-918"],
  [/redirect\s*\(/i, "redirect", "CWE-601"], [/res\.redirect/i, "redirect", "CWE-601"],
  [/new\s+DOMParser/i, "xml_processing", "CWE-611"], [/DOMParser/i, "xml_processing", "CWE-611"],
  [/extractAllTo\s*\(/i, "archive_extraction", "CWE-22"], [/extractTo\s*\(/i, "archive_extraction", "CWE-22"],
  [/ejs\.render|ejs\.compile|pug\.compile|handlebars\.compile|nunjucks\.render|_\s*\.template/i, "template_injection", "CWE-1336"],
  [/xpath\.evaluate|document\.evaluate/i, "xpath_injection", "CWE-643"],
  [/ldap\.search|ldapjs|client\.search/i, "ldap_injection", "CWE-90"],
];
const JS_SANITIZERS: Array<[RegExp, SinkKind[]]> = [
  [/escapeHtml/i, ["html_render"]], [/sanitizeHtml/i, ["html_render"]], [/\.escape\s*\(/i, ["html_render"]],
  [/parameterize/i, ["sql_execution"]], [/escape\s*\(/i, ["sql_execution", "command_execution"]],
  [/Number\s*\(/i, ["sql_execution", "command_execution"]], [/parseInt\s*\(/i, ["sql_execution", "command_execution"]],
  [/\.replace\s*\(/i, ["html_render"]], [/encodeURIComponent/i, ["html_render", "redirect"]],
];

function jsWalk(node: AstNode, out: AstNode[]): AstNode[] {
  if (!node || typeof node !== "object") return out;
  out.push(node);
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "start" || k === "end" || k === "leadingComments" || k === "trailingComments" || k === "innerComments") continue;
    const v = node[k];
    if (Array.isArray(v)) for (const c of v) jsWalk(c, out);
    else if (v && typeof v === "object" && (v.type || v.kind)) jsWalk(v, out);
  }
  return out;
}

const jsAdapter: LanguageAdapter = {
  language: "javascript",
  extensions: [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"],
  parse(code, _file) {
    let ast: AstNode;
    try {
      ast = babelParse(code, {
        sourceType: "unambiguous",
        plugins: ["jsx", "typescript"],
      });
    } catch {
      return { sources: [], sinks: [], sanitizers: [], calls: [], assigns: [] };
    }
    const nodes = jsWalk(ast, []);
    const sources: IrSource[] = [];
    const sinks: IrSink[] = [];
    const sanitizers: IrSanitize[] = [];
    const calls: IrCall[] = [];
    const assigns: IrAssign[] = [];

    const srcText = (n: AstNode): string => {
      try { return code.slice(n.start, n.end); } catch { return ""; }
    };

    for (const n of nodes) {
      // VariableDeclarator: const x = <init>
      if (n.type === "VariableDeclarator" && n.id?.type === "Identifier") {
        const name = n.id.name;
        const initText = srcText(n.init);
        const src = JS_SOURCES.find(([re]) => re.test(initText));
        if (src) sources.push({ variable: name, kind: src[1], line: n.loc?.start?.line ?? 0, attacker_controlled: true });
        // rhs vars for propagation
        const rhsVars: string[] = [];
        for (const c of jsWalk(n.init, [])) if (c.type === "Identifier" && c.name) rhsVars.push(c.name);
        assigns.push({ target: name, sources: rhsVars, line: n.loc?.start?.line ?? 0 });
      }
      // AssignmentExpression: x = <right>
      if (n.type === "AssignmentExpression") {
        // DOM XSS sink: el.innerHTML = <tainted> (property assignment, not a call)
        if (n.left?.type === "MemberExpression" && n.left.property?.name === "innerHTML") {
          const rhsVars: string[] = [];
          for (const c of jsWalk(n.right, [])) if (c.type === "Identifier" && c.name) rhsVars.push(c.name);
          for (const v of rhsVars) sinks.push({ variable: v, kind: "html_render", line: n.loc?.start?.line ?? 0, cwe: "CWE-79" });
        }
        if (n.left?.type === "Identifier") {
          const name = n.left.name;
          const rhsVars: string[] = [];
          for (const c of jsWalk(n.right, [])) if (c.type === "Identifier" && c.name) rhsVars.push(c.name);
          assigns.push({ target: name, sources: rhsVars, line: n.loc?.start?.line ?? 0 });
        }
      }
      // CallExpression: sink / sanitizer / helper
      if (n.type === "CallExpression") {
        const calleeText = srcText(n.callee);
        const fullCallText = srcText(n);
        const argVars: string[] = [];
        for (const c of jsWalk(n.arguments, [])) if (c.type === "Identifier" && c.name) argVars.push(c.name);
        // sink — match against the full call text (so `.query(` with paren matches)
        for (const [re, kind, cwe] of JS_SINKS) {
          // Match against the CALLEE only (not full call text), so a sink nested
          // inside a callback is not double-matched via its enclosing call.
          if (re.test(calleeText + "(")) {
            // parameterized SQL (placeholder + params arg) is safe
            if (kind === "sql_execution" && /(\$\d+|\?)/.test(fullCallText) && /,\s*\[/.test(fullCallText)) continue;
            for (const v of argVars) sinks.push({ variable: v, kind, line: n.loc?.start?.line ?? 0, cwe });
          }
        }
        // sanitizer
        for (const [re, kinds] of JS_SANITIZERS) {
          if (re.test(fullCallText) || re.test(calleeText + "(")) {
            for (const v of argVars) sanitizers.push({ variable: v, neutralizes: kinds, line: n.loc?.start?.line ?? 0 });
          }
        }
        calls.push({ name: calleeText, args: argVars, line: n.loc?.start?.line ?? 0 });
      }
    }

    return { sources, sinks, sanitizers, calls, assigns };
  },
};

// ---------------------------------------------------------------------------
// Python adapter (@lezer/python)
// ---------------------------------------------------------------------------

const PY_SOURCES: Array<[RegExp, SourceKind]> = [
  [/request\.args/i, "http_parameter"], [/request\.form/i, "http_body"], [/request\.get_json/i, "http_body"],
  [/request\.headers/i, "http_header"], [/request\.cookies/i, "http_cookie"], [/request\.files/i, "uploaded_file"],
  [/request\.get/i, "http_parameter"], [/request\.GET/i, "http_parameter"], [/request\.POST/i, "http_body"],
  [/request\.data/i, "http_body"], [/request\.query_params/i, "http_parameter"],
  [/sys\.argv/i, "cli_argument"], [/os\.environ/i, "env_variable"],
];
const PY_SINKS: Array<[RegExp, SinkKind, string?]> = [
  [/os\.system\s*\(/i, "command_execution", "CWE-78"], [/subprocess\.(call|Popen|run)\s*\(/i, "command_execution", "CWE-78"],
  [/eval\s*\(/i, "code_execution", "CWE-94"], [/exec\s*\(/i, "code_execution", "CWE-94"],
  [/\.execute\s*\(/i, "sql_execution", "CWE-89"], [/\.executescript\s*\(/i, "sql_execution", "CWE-89"],
  [/open\s*\(/i, "file_operations", "CWE-434"], [/\.save\s*\(/i, "file_operations", "CWE-434"],
  [/render_template/i, "html_render", "CWE-79"], [/redirect\s*\(/i, "redirect", "CWE-601"],
  [/requests\.(get|post|put|head|request)\s*\(/i, "http_request", "CWE-918"], [/urllib\.request/i, "http_request", "CWE-918"],
  [/pickle\.loads\s*\(/i, "deserialization", "CWE-502"], [/yaml\.load\s*\(/i, "deserialization", "CWE-502"],
  [/os\.popen\s*\(/i, "command_execution", "CWE-78"], [/os\.exec/i, "command_execution", "CWE-78"],
  [/xml\.etree\.ElementTree\.parse|etree\.parse|lxml\.etree\.parse|minidom\.parse|xml\.sax|fromstring/i, "xml_processing", "CWE-611"],
  [/\.extractall\s*\(/i, "archive_extraction", "CWE-22"], [/shutil\.unpack_archive/i, "archive_extraction", "CWE-22"],
  [/render_template_string|jinja2\.Template|env\.from_string/i, "template_injection", "CWE-1336"],
  [/\.xpath\s*\(|etree\.XPath|lxml\.etree\.XPath/i, "xpath_injection", "CWE-643"],
  [/ldap\.search|\.search_s\s*\(/i, "ldap_injection", "CWE-90"],
];
const PY_SANITIZERS: Array<[RegExp, SinkKind[]]> = [
  [/escape\s*\(/i, ["html_render"]], [/html\.escape/i, ["html_render"]], [/bleach/i, ["html_render"]],
  [/\.strip_tags\s*\(/i, ["html_render"]], [/int\s*\(/i, ["sql_execution", "command_execution"]],
  [/float\s*\(/i, ["sql_execution", "command_execution"]], [/shlex\.quote/i, ["command_execution"]],
  [/re\.escape/i, ["sql_execution", "command_execution", "html_render"]],
];

const pythonAdapter: LanguageAdapter = {
  language: "python",
  extensions: [".py", ".pyw"],
  parse(code, _file) {
    const tree = pythonParser.parse(code);
    const sources: IrSource[] = [];
    const sinks: IrSink[] = [];
    const sanitizers: IrSanitize[] = [];
    const calls: IrCall[] = [];
    const assigns: IrAssign[] = [];

    // walk the Lezer tree, collect line info + reconstruct source text per node
    function nodeText(n: AstNode): string {
      try { return code.slice(n.from, n.to); } catch { return ""; }
    }
    function lineOf(n: AstNode): number {
      try { return code.slice(0, n.from).split("\n").length; } catch { return 0; }
    }

    const stack = [tree.topNode];
    while (stack.length) {
      const n = stack.pop()!;
      const text = nodeText(n);
      // assignment: var = ...
      if (n.name === "AssignStatement") {
        // Lezer: AssignStatement has VariableName children + expression
        let target = "";
        let rhs = "";
        let seenAssign = false;
        for (let c = n.firstChild; c; c = c.nextSibling) {
          if (c.name === "VariableName" && !seenAssign) { target = nodeText(c); }
          if (c.name === "AssignOp") { seenAssign = true; rhs = ""; }
          if (seenAssign && c !== n.firstChild) rhs += nodeText(c);
        }
        if (target) {
          const src = PY_SOURCES.find(([re]) => re.test(rhs));
          if (src) sources.push({ variable: target, kind: src[1], line: lineOf(n), attacker_controlled: src[1] !== "cli_argument" && src[1] !== "env_variable" });
          // rhs variables
          const rhsVars: string[] = [];
          const vre = /\b([A-Za-z_][A-Za-z0-9_]*)\b/g; let m;
          while ((m = vre.exec(rhs)) !== null) if (!PY_SOURCES.some(([re]) => re.test(m![1]))) rhsVars.push(m[1]);
          assigns.push({ target, sources: rhsVars, line: lineOf(n) });
        }
      }
      // call expression: name(args)
      if (n.name === "CallExpression") {
        const full = text;
        let callee = "";
        // callee is the first part before '('
        const paren = full.indexOf("(");
        callee = paren > 0 ? full.slice(0, paren) : full;
        // args vars
        const argVars: string[] = [];
        const vre = /\b([A-Za-z_][A-Za-z0-9_]*)\b/g; let m;
        while ((m = vre.exec(full)) !== null) if (m[1] !== callee.trim().split(".").pop()) argVars.push(m[1]);
        for (const [re, kind, cwe] of PY_SINKS) {
          if (!re.test(full)) continue;
          // parameterized SQL (placeholder + params tuple) is safe
          if (kind === "sql_execution" && /\?/.test(full) && /,\s*\(/.test(full)) continue;
          // subprocess list-form (no shell) is safe
          if (kind === "command_execution" && /subprocess/.test(full) && /\[/.test(full)) continue;
          for (const v of argVars) sinks.push({ variable: v, kind, line: lineOf(n), cwe });
        }
        for (const [re, kinds] of PY_SANITIZERS) {
          if (re.test(full)) {
            for (const v of argVars) {
              // A sanitizer neutralizes the VALUE it casts, not the dotted-chain
              // receiver/method names (os.environ.get) or string literals. Without
              // this, a common method name like `get` neutralized in one place
              // (`int(os.environ.get(...))`) pollutes the `get` in `request.args.get`
              // elsewhere and wrongly suppresses real SQLi/command findings.
              if (new RegExp(`\\b${v}\\s*[.(]`).test(full)) continue;
              sanitizers.push({ variable: v, neutralizes: kinds, line: lineOf(n) });
            }
          }
        }
        calls.push({ name: callee, args: argVars, line: lineOf(n) });
      }
      for (let c = n.firstChild; c; c = c.nextSibling) stack.push(c);
    }

    return { sources, sinks, sanitizers, calls, assigns };
  },
};

// ---------------------------------------------------------------------------
// Java adapter (java-parser)
// ---------------------------------------------------------------------------

const JAVA_SOURCES: Array<[RegExp, SourceKind]> = [
  [/getParameter\s*\(/i, "http_parameter"], [/getHeader\s*\(/i, "http_header"],
  [/getCookies\s*\(/i, "http_cookie"], [/getParameterMap/i, "http_parameter"],
  [/getInputStream\s*\(/i, "raw_body"], [/args\[/i, "cli_argument"],
];
const JAVA_SINKS: Array<[RegExp, SinkKind, string?]> = [
  [/\.executeQuery\s*\(/i, "sql_execution", "CWE-89"], [/\.execute\s*\(/i, "sql_execution", "CWE-89"],
  [/Runtime\.getRuntime\(\)\.exec\s*\(/i, "command_execution", "CWE-78"], [/ProcessBuilder/i, "command_execution", "CWE-78"],
  [/\.exec\s*\(/i, "command_execution", "CWE-78"], [/Runtime\.getRuntime/i, "command_execution", "CWE-78"],
  [/\.write\s*\(/i, "html_render", "CWE-79"], [/\.println\s*\(/i, "html_render", "CWE-79"],
  [/ObjectInputStream/i, "deserialization", "CWE-502"], [/readObject\s*\(/i, "deserialization", "CWE-502"],
  [/new File\s*\(/i, "file_operations", "CWE-434"], [/\.getInputStream\s*\(/i, "http_request", "CWE-918"],
  [/new URL\s*\(/i, "http_request", "CWE-918"], [/openConnection\s*\(/i, "http_request", "CWE-918"],
  [/DocumentBuilder|SAXParser|XMLReader/i, "xml_processing", "CWE-611"], [/\.parse\s*\(/i, "xml_processing", "CWE-611"],
  [/sendRedirect\s*\(/i, "redirect", "CWE-601"], [/\.forward\s*\(/i, "redirect", "CWE-601"],
  [/ZipInputStream|ZipFile|getNextEntry|ZipEntry/i, "archive_extraction", "CWE-22"],
  [/Velocity\.evaluate|Freemarker|Template\.process|\.process\s*\(/i, "template_injection", "CWE-1336"],
  [/XPath\.evaluate|XPath\.compile|XPathExpression|XPathFactory/i, "xpath_injection", "CWE-643"],
  [/DirContext\.search|LdapTemplate\.search|InitialDirContext/i, "ldap_injection", "CWE-90"],
];
const JAVA_SANITIZERS: Array<[RegExp, SinkKind[]]> = [
  [/HtmlUtils\.htmlEscape/i, ["html_render"]], [/StringEscapeUtils\.escapeHtml/i, ["html_render"]],
  [/PreparedStatement/i, ["sql_execution"]], [/\.setString\s*\(/i, ["sql_execution"]],
  [/Integer\.parseInt/i, ["sql_execution", "command_execution"]], [/Long\.parseLong/i, ["sql_execution", "command_execution"]],
];


const javaAdapter: LanguageAdapter = {
  language: "java",
  extensions: [".java"],
  parse(code, _file) {
    const sources: IrSource[] = [];
    const sinks: IrSink[] = [];
    const sanitizers: IrSanitize[] = [];
    const calls: IrCall[] = [];
    const assigns: IrAssign[] = [];

    // Java CST from java-parser (chevrotain) is verbose; rather than walking the
    // full CST, use a token/line-oriented approach: detect assignments + calls
    // via regex on source text, with line numbers.
    const lines = code.split("\n");
    const assignRe = /([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);/g;
    let m;
    while ((m = assignRe.exec(code)) !== null) {
      const varName = m[2];
      const rhs = m[3];
      const line = code.slice(0, m.index).split("\n").length;
      const src = JAVA_SOURCES.find(([re]) => re.test(rhs));
      if (src) sources.push({ variable: varName, kind: src[1], line, attacker_controlled: src[1] !== "cli_argument" });
      assigns.push({ target: varName, sources: [], line });
    }
    // Spring/JAX-RS annotations: @RequestParam / @PathVariable / @RequestBody /
    // @RequestHeader / @CookieValue mark a method parameter as attacker-controlled.
    const annotRe = /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)(?:\([^)]*\))?\s+(?:[\w<>,\.\[\]\s]+\s+)?([A-Za-z_]\w*)/g;
    while ((m = annotRe.exec(code)) !== null) {
      const varName = m[1];
      const line = code.slice(0, m.index).split("\n").length;
      sources.push({ variable: varName, kind: "http_parameter", line, attacker_controlled: true });
      assigns.push({ target: varName, sources: [], line });
    }
    // sink calls: .exec(...), .executeQuery(...), sendRedirect(...), etc.
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const [re, kind, cwe] of JAVA_SINKS) {
        if (re.test(line)) {
          const argVars: string[] = [];
          const vre = /([A-Za-z_][A-Za-z0-9_]*)/g; let vm;
          while ((vm = vre.exec(line)) !== null) {
            // Keep only likely variable names: skip known methods/types and
            // SQL keywords/type names (which start uppercase) so the tainted
            // variable is not pushed past the slice window.
            const id = vm[1];
            if (/Runtime|getRuntime|ProcessBuilder|ObjectInputStream|HtmlUtils|StringEscapeUtils|PreparedStatement|Integer|Long|sendRedirect|forward|executeQuery|execute|exec|createStatement|getConnection|prepareStatement|getString|DriverManager/.test(id)) continue;
            if (/^[A-Z]/.test(id)) continue; // SQL keywords + Java type names
            argVars.push(id);
          }
          for (const v of argVars.slice(0, 8)) sinks.push({ variable: v, kind, line: i + 1, cwe });
        }
      }
      for (const [re, kinds] of JAVA_SANITIZERS) {
        if (re.test(line)) {
          const vre = /([A-Za-z_][A-Za-z0-9_]*)/g; let vm;
          while ((vm = vre.exec(line)) !== null) sanitizers.push({ variable: vm[1], neutralizes: kinds, line: i + 1 });
        }
      }
    }

    return { sources, sinks, sanitizers, calls, assigns };
  },
};

// ---------------------------------------------------------------------------
// Rust adapter (regex/line-oriented — Rust's ownership model makes the classic
// web sinks map cleanly; the memory-safety surface is handled by the
// rust_unsafe complex-bugs detector, not the taint engine)
// ---------------------------------------------------------------------------

const RUST_SOURCES: Array<[RegExp, SourceKind]> = [
  [/env::args\s*\(|args_os\s*\(/, "cli_argument"],
  [/stdin\s*\(\s*\)|read_line\s*\(/, "raw_body"],
  [/\b(?:Query|Form|Json|Path)\b|web::(?:Query|Json|Form|Path)|req\.(?:query|params|param|form|query_string)/, "http_parameter"],
  [/env::var\s*\(|env::var_os\s*\(/, "env_variable"],
];

const RUST_SINKS: Array<[RegExp, SinkKind, string?]> = [
  // command execution — the shell form (sh -c / bash -c / cmd /c) is the vuln;
  // the list form Command::new("ls").arg(x) is safe.
  [/Command::new|process::Command/, "command_execution", "CWE-78"],
  // SQL — runtime `sqlx::query(&format!(...))` is vuln; the `query!` compile-time
  // macro is safe (checked against the schema at build time).
  [/sqlx::query(?:_as)?\s*\(|sqlx::raw_sql|\.query\s*\(|\.execute\s*\(|rusqlite|diesel::/, "sql_execution", "CWE-89"],
  // SSRF — reqwest/hyper fetching an attacker-supplied URL.
  [/reqwest::get|reqwest::Client|hyper::|\.get\s*\(|\.post\s*\(|\.put\s*\(|\.request\s*\(/, "http_request", "CWE-918"],
  // path traversal — fs reads/writes keyed on an attacker-supplied path.
  [/std::fs::(read_to_string|read|write|remove_file|copy|rename)|File::open\s*\(|fs::(read|write|remove_file|copy)\s*\(/, "path_traversal", "CWE-22"],
  // deserialization — serde/bincode/toml on untrusted bytes (bincode is unsafe for untrusted input).
  [/serde_json::from_(str|slice)|bincode::deserialize|serde_yaml::from_str|toml::from_str|\.deserialize\s*\(/, "deserialization", "CWE-502"],
];

const RUST_SANITIZERS: Array<[RegExp, SinkKind[]]> = [
  // canonicalize resolves the path against the FS root (mitigates traversal)
  [/canonicalize\s*\(/, ["path_traversal"]],
  // the compile-time-checked query! macro is safe (no runtime string building)
  [/query(_as)?!\s*\(/, ["sql_execution"]],
];

const rustAdapter: LanguageAdapter = {
  language: "rust",
  extensions: [".rs"],
  parse(code, _file) {
    const sources: IrSource[] = [];
    const sinks: IrSink[] = [];
    const sanitizers: IrSanitize[] = [];
    const calls: IrCall[] = [];
    const assigns: IrAssign[] = [];

    // `let [mut] name = rhs;` — assign + source detection.
    const assignRe = /let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?);/g;
    let m: RegExpExecArray | null;
    while ((m = assignRe.exec(code)) !== null) {
      const varName = m[1];
      const rhs = m[2];
      const line = code.slice(0, m.index).split("\n").length;
      const src = RUST_SOURCES.find(([re]) => re.test(rhs));
      if (src) sources.push({ variable: varName, kind: src[1], line, attacker_controlled: src[1] !== "cli_argument" && src[1] !== "env_variable" });
      const rhsVars: string[] = [];
      const vre = /([a-z_][a-z0-9_]*)/g; let vm: RegExpExecArray | null;
      while ((vm = vre.exec(rhs)) !== null) {
        const v = vm[1];
        if (!RUST_SOURCES.some(([re]) => re.test(v))) rhsVars.push(v);
      }
      assigns.push({ target: varName, sources: rhsVars.slice(0, 8), line });
    }

    // Axum/Actix extractors as function params: fn h(Query(q): Query<...>, ...)
    const extractorRe = /\b(?:Query|Form|Json|Path)\s*\(\s*([a-z_][a-z0-9_]*)\s*\)/g;
    while ((m = extractorRe.exec(code)) !== null) {
      const line = code.slice(0, m.index).split("\n").length;
      sources.push({ variable: m[1], kind: "http_parameter", line, attacker_controlled: true });
      assigns.push({ target: m[1], sources: [], line });
    }

    const lines = code.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const [re, kind, cwe] of RUST_SINKS) {
        if (!re.test(line)) continue;
        // skip compile-time-checked SQL macro (query! / query_as!)
        if (kind === "sql_execution" && /query(_as)?!\s*\(/.test(line)) continue;
        const argVars: string[] = [];
        const vre = /([a-z_][a-z0-9_]*)/g; let vm: RegExpExecArray | null;
        while ((vm = vre.exec(line)) !== null) {
          const id = vm[1];
          // skip method/API names + keywords so the tainted variable survives the slice
          if (/^(new|let|mut|arg|args|command|process|std|sqlx|query|query_as|execute|reqwest|client|get|post|put|request|fs|file|open|read_to_string|read|write|remove_file|copy|rename|serde_json|from_str|from_slice|bincode|deserialize|toml|yaml|format|unwrap|expect|env|args|stdin|read_line)$/.test(id)) continue;
          argVars.push(id);
        }
        for (const v of argVars.slice(0, 8)) sinks.push({ variable: v, kind, line: i + 1, cwe });
      }
      for (const [re, kinds] of RUST_SANITIZERS) {
        if (re.test(line)) {
          const vre = /([a-z_][a-z0-9_]*)/g; let vm: RegExpExecArray | null;
          while ((vm = vre.exec(line)) !== null) sanitizers.push({ variable: vm[1], neutralizes: kinds, line: i + 1 });
        }
      }
    }

    return { sources, sinks, sanitizers, calls, assigns };
  },
};

// ---------------------------------------------------------------------------
// Register all adapters
// ---------------------------------------------------------------------------

registerLanguage(phpAdapter);
registerLanguage(jsAdapter);
registerLanguage(pythonAdapter);
registerLanguage(javaAdapter);
registerLanguage(rustAdapter);

export { phpAdapter, jsAdapter, pythonAdapter, javaAdapter, rustAdapter };
