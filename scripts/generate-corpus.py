#!/usr/bin/env python3
"""Generate the Blitz Strike benchmark corpus (Phase 3).

Bootstraps bench/corpus/*.md from a systematic matrix of
(language x sink_type x vulnerable/patched). Each fixture is a deterministic,
self-contained code sample with a label. Vulnerable fixtures MUST be detected;
patched fixtures MUST NOT be flagged (sanitizer / prepared statement /
validation / whitelist).

Usage: python3 scripts/generate-corpus.py
"""
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
CORPUS = os.path.join(ROOT, "bench", "corpus")

# ---------------------------------------------------------------------------
# Template matrix
# ---------------------------------------------------------------------------

T = []

def add(pid, lang, vuln, sink, code):
    T.append({"id": pid, "language": lang, "vulnerable": vuln, "sink_type": sink, "code": code.strip()})

# --- PHP (AST engine) ---
add("php-sqli-vuln", "php", True, "sql_execution", '<?php\n$id = $_GET["id"];\n$wpdb->query("SELECT * FROM t WHERE id=$id");')
add("php-sqli-prepared", "php", False, "sql_execution", '<?php\n$id = $_GET["id"];\n$wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id=%d", $id));')
add("php-sqli-esc", "php", False, "sql_execution", '<?php\n$id = $_GET["id"];\n$q = $wpdb->query("SELECT * FROM t WHERE id=" . esc_sql($id));')

add("php-xss-vuln", "php", True, "html_render", '<?php\n$name = $_GET["name"];\necho $name;')
add("php-xss-sanitized", "php", False, "html_render", '<?php\n$name = $_GET["name"];\necho htmlspecialchars($name);')
add("php-xss-eschtml", "php", False, "html_render", '<?php\n$name = $_GET["name"];\necho esc_html($name);')

add("php-cmd-vuln", "php", True, "command_execution", '<?php\n$cmd = $_GET["cmd"];\nsystem($cmd);')
add("php-cmd-escaped", "php", False, "command_execution", '<?php\n$cmd = $_GET["cmd"];\nsystem(escapeshellarg($cmd));')
add("php-cmd-intval", "php", False, "command_execution", '<?php\n$n = $_GET["n"];\nsystem("ping -c " . intval($n));')

add("php-codeexec-vuln", "php", True, "code_execution", '<?php\n$code = $_GET["code"];\neval($code);')
add("php-codeexec-assert", "php", True, "code_execution", '<?php\n$code = $_GET["code"];\nassert($code);')

add("php-fileupload-vuln", "php", True, "file_operations", '<?php\n$f = $_FILES["u"];\nmove_uploaded_file($f["tmp_name"], "/uploads/" . $f["name"]);')
add("php-fileupload-sanitized", "php", False, "file_operations", '<?php\n$f = $_FILES["u"];\nmove_uploaded_file($f["tmp_name"], "/uploads/" . sanitize_file_name($f["name"]));')
add("php-filewrite-vuln", "php", True, "file_operations", '<?php\n$data = $_POST["data"];\nfile_put_contents("/tmp/log.txt", $data);')

add("php-include-vuln", "php", True, "file_inclusion", '<?php\n$page = $_GET["page"];\ninclude($page . ".php");')
add("php-include-whitelist", "php", False, "file_inclusion", '<?php\n$page = $_GET["page"];\n$allow = ["home", "about"];\nif (in_array($page, $allow)) { include($page . ".php"); }')

add("php-unserialize-vuln", "php", True, "deserialization", '<?php\n$data = $_COOKIE["data"];\nunserialize($data);')

add("php-ssrf-vuln", "php", True, "http_request", '<?php\n$url = $_GET["url"];\nfile_get_contents($url);')
add("php-ssrf-wpremote", "php", True, "http_request", '<?php\n$url = $_GET["url"];\nwp_remote_get($url);')

add("php-redirect-vuln", "php", True, "redirect", '<?php\n$url = $_GET["url"];\nheader("Location: " . $url);')
add("php-redirect-safe", "php", False, "redirect", '<?php\n$url = $_GET["url"];\nwp_safe_redirect($url);')

add("php-xxe-vuln", "php", True, "xml_processing", '<?php\n$xml = $_POST["xml"];\nsimplexml_load_string($xml);')

add("php-zipslip-vuln", "php", True, "archive_extraction", '<?php\n$dest = $_GET["dest"];\n$zip = new ZipArchive();\n$zip->extractTo($dest);')

# PHP interprocedural / byref / return (EAGLE-EYE 2.0 coverage)
add("php-sqli-interproc", "php", True, "sql_execution", '<?php\nfunction run_q($id) { global $wpdb; $wpdb->query("SELECT * FROM t WHERE id=$id"); }\n$id = $_GET["id"];\nrun_q($id);')
add("php-xss-return", "php", True, "html_render", '<?php\nfunction id($x) { return $x; }\necho id($_GET["q"]);')
add("php-cmd-byref", "php", True, "command_execution", '<?php\nfunction fill(&$out) { $out = $_GET["cmd"]; }\n$c = "";\nfill($c);\nsystem($c);')
add("php-cmd-transitive", "php", True, "command_execution", '<?php\nfunction a($v) { b($v); }\nfunction b($v) { system($v); }\na($_GET["cmd"]);')
add("php-xss-ternary", "php", True, "html_render", '<?php\n$t = isset($_GET["t"]) ? $_GET["t"] : "safe";\necho $t;')
add("php-sqli-authgated", "php", True, "sql_execution", '<?php\nfunction del($id) { if (current_user_can("x")) { global $wpdb; $wpdb->query("DELETE FROM t WHERE id=$id"); } }\ndel($_GET["id"]);')

# --- JavaScript (Node.js) ---
add("js-sqli-vuln", "javascript", True, "sql_execution", 'const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id=" + id);')
add("js-sqli-param", "javascript", False, "sql_execution", 'const id = req.query.id;\ndb.query("SELECT * FROM t WHERE id=?", [id]);')
add("js-xss-vuln", "javascript", True, "html_render", 'const x = req.query.x;\nres.send(x);')
add("js-xss-escape", "javascript", False, "html_render", 'const x = req.query.x;\nres.send(escapeHtml(x));')
add("js-cmd-vuln", "javascript", True, "command_execution", 'const c = req.query.cmd;\nexec("ls " + c);')
add("js-cmd-spawn", "javascript", False, "command_execution", 'const c = req.query.cmd;\nspawn("ls", [c]);')
add("js-ssrf-vuln", "javascript", True, "http_request", 'const u = req.query.url;\nhttp.get(u, cb);')
add("js-pathtraversal-vuln", "javascript", True, "file_operations", 'const f = req.query.file;\nfs.readFile("/data/" + f);')
add("js-eval-vuln", "javascript", True, "code_execution", 'const c = req.body.code;\neval(c);')
add("js-redirect-vuln", "javascript", True, "redirect", 'const u = req.query.url;\nres.redirect(u);')

# --- Python ---
add("py-sqli-vuln", "python", True, "sql_execution", 'import sqlite3\nid = request.args.get("id")\ncursor.execute(f"SELECT * FROM t WHERE id={id}")')
add("py-sqli-param", "python", False, "sql_execution", 'import sqlite3\nid = request.args.get("id")\ncursor.execute("SELECT * FROM t WHERE id=?", (id,))')
add("py-cmd-vuln", "python", True, "command_execution", 'import os\ncmd = request.args.get("cmd")\nos.system(cmd)')
add("py-cmd-subprocess", "python", False, "command_execution", 'import subprocess\ncmd = request.args.get("cmd")\nsubprocess.run(["ls", cmd])')
add("py-xss-vuln", "python", True, "html_render", 'name = request.args.get("name")\nreturn render_template_string("<p>" + name + "</p>")')
add("py-ssrf-vuln", "python", True, "http_request", 'import requests\nurl = request.args.get("url")\nrequests.get(url)')
add("py-pathtraversal-vuln", "python", True, "file_operations", 'f = request.args.get("file")\nopen("/data/" + f)')
add("py-deser-vuln", "python", True, "deserialization", 'import pickle\ndata = request.get_data()\npickle.loads(data)')
add("py-deser-json", "python", False, "deserialization", 'import json\ndata = request.get_data()\njson.loads(data)')
add("py-eval-vuln", "python", True, "code_execution", 'code = request.args.get("code")\neval(code)')

# --- Java ---
add("java-sqli-vuln", "java", True, "sql_execution", 'String id = request.getParameter("id");\nStatement st = conn.createStatement();\nst.executeQuery("SELECT * FROM t WHERE id=" + id);')
add("java-sqli-prep", "java", False, "sql_execution", 'String id = request.getParameter("id");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");\nps.setString(1, id);')
add("java-cmd-vuln", "java", True, "command_execution", 'String cmd = request.getParameter("cmd");\nRuntime.getRuntime().exec(cmd);')
add("java-xss-vuln", "java", True, "html_render", 'String x = request.getParameter("x");\nresponse.getWriter().write(x);')
add("java-deser-vuln", "java", True, "deserialization", 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nois.readObject();')
add("java-xxe-vuln", "java", True, "xml_processing", 'InputStream in = request.getInputStream();\nDocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\nDocumentBuilder db = dbf.newDocumentBuilder();\ndb.parse(in);')
add("java-ssrf-vuln", "java", True, "http_request", 'String url = request.getParameter("url");\nURL u = new URL(url);\nu.openConnection();')

# --- extra variants for breadth ---
add("php-sqli-getvar", "php", True, "sql_execution", '<?php\n$id = $_GET["id"];\n$wpdb->get_var("SELECT name FROM t WHERE id=$id");')
add("php-sqli-whereraw", "php", True, "sql_execution", '<?php\n$id = $_GET["id"];\nDB::table("t")->whereRaw("id = $id")->get();')
add("php-cmd-shell-exec", "php", True, "command_execution", '<?php\n$cmd = $_GET["cmd"];\nshell_exec($cmd);')
add("php-cmd-passthru", "php", True, "command_execution", '<?php\n$cmd = $_GET["cmd"];\npassthru($cmd);')
add("php-xss-attr", "php", False, "html_render", '<?php\n$v = $_GET["v"];\necho esc_attr($v);')
add("php-fileupload-name", "php", True, "file_operations", '<?php\n$f = $_FILES["f"];\nmove_uploaded_file($f["tmp_name"], $f["name"]);')
add("php-include-require", "php", True, "file_inclusion", '<?php\n$m = $_GET["m"];\nrequire($m . ".php");')
add("php-ssrf-curl", "php", True, "http_request", '<?php\n$u = $_GET["u"];\n$ch = curl_init();\ncurl_setopt($ch, CURLOPT_URL, $u);\ncurl_exec($ch);')

# --- sanitizer-neutralizes variants (must NOT be detected) ---
add("php-xss-htmlentities", "php", False, "html_render", '<?php\n$v = $_GET["v"];\necho htmlentities($v);')
add("php-cmd-escapeshellcmd", "php", False, "command_execution", '<?php\n$c = $_GET["c"];\nsystem(escapeshellcmd($c));')
add("php-include-intval", "php", False, "file_inclusion", '<?php\n$id = $_GET["id"];\ninclude("/pages/" . intval($id) . ".php");')
add("php-sqli-filter", "php", False, "sql_execution", '<?php\n$id = filter_var($_GET["id"], FILTER_VALIDATE_INT);\n$wpdb->query("SELECT * FROM t WHERE id=$id");')

# --- auth-gated variants (lower priority, but still detected) ---
add("php-xss-authgated", "php", True, "html_render", '<?php\nif (current_user_can("edit")) { echo $_GET["x"]; }')
add("php-cmd-authgated", "php", True, "command_execution", '<?php\nif (is_user_logged_in()) { system($_GET["c"]); }')

# --- round 2: broader sink/sanitizer/source coverage (100+ corpus) ---
# PHP
add("php-ssrf-wppost", "php", True, "http_request", '<?php\n$url = $_GET["url"];\nwp_remote_post($url, []);')
add("php-cmd-popen", "php", True, "command_execution", '<?php\n$cmd = $_GET["cmd"];\npopen($cmd, "r");')
add("php-xss-print", "php", True, "html_render", '<?php\n$name = $_GET["name"];\nprint $name;')
add("php-sqli-getresults", "php", True, "sql_execution", '<?php\n$id = $_GET["id"];\n$wpdb->get_results("SELECT * FROM t WHERE id=$id");')
add("php-include-once", "php", True, "file_inclusion", '<?php\n$page = $_GET["page"];\ninclude_once($page . ".php");')
add("php-deser-json", "php", False, "deserialization", '<?php\n$data = $_COOKIE["data"];\njson_decode($data);')
add("php-cmd-absint", "php", False, "command_execution", '<?php\n$n = $_GET["n"];\nsystem("ping -c " . absint($n));')
add("php-xss-sanitizetext", "php", False, "html_render", '<?php\n$v = $_GET["v"];\necho sanitize_text_field($v);')
add("php-sqli-filterinput", "php", False, "sql_execution", '<?php\n$id = filter_input(INPUT_GET, "id", FILTER_VALIDATE_INT);\n$wpdb->query("SELECT * FROM t WHERE id=$id");')
add("php-include-sanitized", "php", False, "file_inclusion", '<?php\n$f = $_GET["f"];\ninclude(sanitize_file_name($f));')
add("php-xss-escurl", "php", False, "redirect", '<?php\n$url = $_GET["url"];\nwp_safe_redirect(esc_url($url));')

# JavaScript
add("js-ssrf-axios", "javascript", True, "http_request", 'const u = req.query.url;\naxios.get(u);')
add("js-ssrf-fetch", "javascript", True, "http_request", 'const u = req.query.url;\nfetch(u);')
add("js-cmd-execsync", "javascript", True, "command_execution", 'const c = req.query.cmd;\nexecSync("ls " + c);')
add("js-xss-innerhtml", "javascript", True, "html_render", 'const x = req.query.x;\nel.innerHTML = x;')
add("js-xss-documentwrite", "javascript", True, "html_render", 'const x = req.query.x;\ndocument.write(x);')
add("js-pathtraversal-readsync", "javascript", True, "path_traversal", 'const f = req.query.file;\nfs.readFileSync("/data/" + f);')
add("js-filewrite", "javascript", True, "file_operations", 'const d = req.body.data;\nfs.writeFile("/tmp/x", d);')
add("js-redirect-encodeuri", "javascript", False, "redirect", 'const u = req.query.u;\nres.redirect(encodeURIComponent(u));')

# Python
add("py-ssrf-urllib", "python", True, "http_request", 'import urllib.request\nurl = request.args.get("url")\nurllib.request.urlopen(url)')
add("py-cmd-popen", "python", True, "command_execution", 'import os\ncmd = request.args.get("cmd")\nos.popen(cmd)')
add("py-cmd-shlex", "python", False, "command_execution", 'import shlex, subprocess\ncmd = request.args.get("cmd")\nsubprocess.run(shlex.quote(cmd))')
add("py-deser-yaml", "python", True, "deserialization", 'import yaml\ndata = request.get_data()\nyaml.load(data)')
add("py-xss-escape", "python", False, "html_render", 'name = request.args.get("name")\nreturn render_template_string(escape(name))')
add("py-sqli-executescript", "python", True, "sql_execution", 'import sqlite3\nid = request.args.get("id")\ncursor.executescript(f"DELETE FROM t WHERE id={id}")')

# Java
add("java-cmd-processbuilder", "java", True, "command_execution", 'String cmd = request.getParameter("cmd");\nnew ProcessBuilder(cmd).start();')
add("java-ssrf-httpurl", "java", True, "http_request", 'String url = request.getParameter("url");\nHttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();')
add("java-xss-println", "java", True, "html_render", 'String x = request.getParameter("x");\nresponse.getWriter().println(x);')
add("java-xss-escape", "java", False, "html_render", 'String x = request.getParameter("x");\nresponse.getWriter().write(HtmlUtils.htmlEscape(x));')
add("java-sqli-execute", "java", True, "sql_execution", 'String id = request.getParameter("id");\nst.execute("DELETE FROM t WHERE id=" + id);')
add("java-deser-readunshared", "java", True, "deserialization", 'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nois.readUnshared();')

# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def render(entry):
    return (f"- id: {entry['id']}\n"
            f"- language: {entry['language']}\n"
            f"- vulnerable: {'true' if entry['vulnerable'] else 'false'}\n"
            f"- sink_type: {entry['sink_type']}\n"
            f"```{entry['language']}\n"
            f"{entry['code']}\n"
            f"```\n")

def main():
    os.makedirs(CORPUS, exist_ok=True)
    seen = set()
    for e in T:
        if e["id"] in seen:
            raise SystemExit(f"duplicate id {e['id']}")
        seen.add(e["id"])
        with open(os.path.join(CORPUS, e["id"] + ".md"), "w") as f:
            f.write(render(e))
    print(f"generated {len(T)} fixtures -> {CORPUS}")
    vuln = sum(1 for e in T if e["vulnerable"])
    patched = sum(1 for e in T if not e["vulnerable"])
    print(f"  vulnerable: {vuln}, patched/safe: {patched}")

if __name__ == "__main__":
    main()
