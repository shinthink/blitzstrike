/** Deterministic sink scanner for LEAKED content.
 *
 * When a response leaks source, a traceback, a debug page, a config file, or a
 * credential dump, the driving agent must not rely on eyeballing it. This module
 * scans arbitrary leaked text for dangerous sinks (RCE, SSTI, SQLi, SSRF, LFI,
 * secrets, hardcoded creds, deserialization, XXE) and returns each as a
 * classified hit with a line + snippet + suggested next action. Works on ANY
 * leaked text, not just Werkzeug.
 */

export interface SinkHit {
  type: string; // rce | ssti | sqli | ssrf | lfi | secret | credential | deserialization | xxe
  label: string; // human label, e.g. "eval()"
  line: number;
  snippet: string; // trimmed surrounding text
  next: string; // suggested follow-up action
}

const NEXT: Record<string, string> = {
  rce: "test the sink with a marker payload (eval -> '1+1' -> 2, then sleep vs no-sleep / write a marker file) — this is direct RCE",
  ssti: "probe {{7*7}} / {{7*'7'}} for evaluation; if it evaluates, it is SSTI -> RCE",
  sqli: "confirm with quote/boolean/UNION via strike_verify; enumerate schema + dump sensitive tables",
  ssrf: "inject a canary/internal URL and watch for a callback or metadata reflection",
  lfi: "read /etc/passwd, configs, keys, machine-id — completes Werkzeug PIN or credential theft chains",
  secret: "a leaked secret lets you forge sessions/tokens (e.g. Flask SECRET_KEY -> flask-unsign) or authenticate directly",
  credential: "try the leaked credential against login / basic-auth / admin surfaces",
  deserialization: "craft a serialized payload (pickle/unserialize/yaml) -> RCE chain",
  xxe: "send an XML entity to read files or hit internal SSRF",
};

interface Pattern {
  type: keyof typeof NEXT;
  label: string;
  regex: RegExp;
}

const PATTERNS: Pattern[] = [
  { type: "rce", label: "eval()", regex: /\beval\s*\(/i },
  { type: "rce", label: "exec()", regex: /\bexec\s*\(/i },
  { type: "rce", label: "os.system()", regex: /\bos\.system\s*\(/i },
  { type: "rce", label: "os.popen()", regex: /\bos\.popen\s*\(/i },
  { type: "rce", label: "subprocess", regex: /\bsubprocess\.(?:call|run|Popen|check_output)/i },
  { type: "rce", label: "shell_exec/passthru/proc_open", regex: /\b(?:shell_exec|passthru|proc_open|popen)\s*\(/i },
  { type: "rce", label: "child_process.exec", regex: /\bchild_process\.exec(?:Sync)?\s*\(/i },
  { type: "ssti", label: "render_template_string", regex: /render_template_string/i },
  { type: "ssti", label: "jinja2 Template", regex: /jinja2\s*\.\s*Template|Template\s*\(/i },
  { type: "ssti", label: "string .format on input", regex: /\.format\s*\(\s*(?:request|input|param|payload)/i },
  { type: "sqli", label: "SQL f-string/concatenation", regex: /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|LIKE)[^'"\n]{0,40}['"]\s*[+}].*?(?:query|input|param|id|user|title|search|q)/is },
  { type: "sqli", label: "cursor.execute with input", regex: /(?:execute|executemany)\s*\([^)]*[+%f]/i },
  { type: "ssrf", label: "requests.get/post", regex: /\brequests\.(?:get|post|put|head)\s*\(/i },
  { type: "ssrf", label: "urllib/urlopen", regex: /\b(?:urllib\.request|urlopen|httpx\.(?:get|post))\s*\(/i },
  { type: "ssrf", label: "file_get_contents/curl", regex: /\b(?:file_get_contents|curl_exec|curl_init)\s*\(/i },
  { type: "lfi", label: "file read", regex: /\b(?:open|readfile|file_get_contents|include|require)\s*\(\s*[^)]*(?:request|input|param|path|file|\.\.)/i },
  { type: "secret", label: "SECRET_KEY", regex: /(?:SECRET_KEY|secret_key)\b[^\n]{0,40}=[^\n]{0,10}["'][^"']{3,}["']/i },
  { type: "secret", label: "API key/token", regex: /(?:api[_-]?key|access[_-]?key|auth[_-]?token|JWT_SECRET)\b[^\n]{0,40}=[^\n]{0,10}["'][^"']{3,}["']/i },
  { type: "credential", label: "password assignment", regex: /(?:password|passwd|pass|pwd)\s*[:=]\s*["'][^"']{3,}["']/i },
  { type: "credential", label: "hardcoded cred", regex: /\b(?:admin|root|user(?:name)?)\s*[:=]\s*["'][^"']{3,}["']/i },
  { type: "deserialization", label: "pickle/unserialize/yaml", regex: /\b(?:pickle\.loads|unserialize\s*\(|yaml\.load\s*\(|marshal\.loads|jsonpickle)/i },
  { type: "xxe", label: "XML parse", regex: /\b(?:etree\.(?:parse|fromstring)|lxml\.etree|xml\.(?:dom|sax)|DocumentBuilder|simplexml_load)/i },
];

/** Scan leaked text for dangerous sinks. Returns classified hits, deduped. */
export function scanSinks(text: string): SinkHit[] {
  if (!text || text.length < 3) return [];
  const lines = text.split("\n");
  const hits: SinkHit[] = [];
  const seen = new Set<string>();

  for (const pat of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!pat.regex.test(line)) continue;
      pat.regex.lastIndex = 0;
      const key = `${pat.type}:${pat.label}:${line.trim().slice(0, 60)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({
        type: pat.type,
        label: pat.label,
        line: i + 1,
        snippet: line.trim().slice(0, 160),
        next: NEXT[pat.type],
      });
    }
  }
  // Order: RCE > secret > credential > sqli > ssrf > ssti > lfi > deserialization > xxe
  const rank: Record<string, number> = { rce: 0, secret: 1, credential: 2, sqli: 3, ssrf: 4, ssti: 5, lfi: 6, deserialization: 7, xxe: 8 };
  return hits.sort((a, b) => (rank[a.type] ?? 99) - (rank[b.type] ?? 99));
}

const LEAK_SIGNATURES: RegExp[] = [
  /Traceback \(most recent call last\)/i,
  /werkzeug|jinja2\.exceptions|flask\.app/i,
  /Django Version|Request Method:|Settings:/i,
  /Whoops, looks like something went wrong/i,
  /(?:PHP )?(?:Fatal error|Parse error|Warning|Notice):/i,
  /Stack trace:|#\d+ .*\.php\(\d+\)/i,
  /Exception in thread|at \w+\.\w+\(.*\)\s*$/m,
  /^\s+at (?:Object\.|com\.|org\.|net\.)\S+/m,
  /Interactive debugger|debug=True|__debugger__/i,
  /Error:\s.*\n\s+at\s/m,
];

/** Detect whether a response body is leaking source/traceback/error detail. */
export function detectSourceLeak(body: string): boolean {
  if (!body) return false;
  const head = body.slice(0, 120000);
  return LEAK_SIGNATURES.some((re) => re.test(head));
}
