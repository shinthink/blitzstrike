/** Live nuclei-templates CVE corpus loader.
 *
 *  Reads the canonical `projectdiscovery/nuclei-templates` `http/cves/**`
 *  tree DIRECTLY when it is present on disk (so the fingerprint corpus is
 *  always current after `nuclei -update-templates`), and falls back to the
 *  bundled `intelligence/cve-corpus.json` when nuclei-templates is not
 *  installed. The parsed corpus is cached; invalidate it after a template
 *  refresh with `invalidateCorpusCache()`.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

export interface CorpusEntry {
  cve: string;
  name: string;
  product: string;
  severity?: string;
  epss: number;
  cwe?: string;
  match?: string;
}

// Generic infrastructure/tech tokens that cause cross-product false positives.
const GENERIC = new Set([
  "php", "python", "java", "javascript", "node", "nodejs", "ruby", "perl", "go", "golang", "rust", "html", "css", "xml", "json", "shell", "bash", "sql",
  "apache", "nginx", "iis", "tomcat", "jboss", "weblogic", "websphere", "litespeed", "lighttpd", "caddy",
  "mysql", "mariadb", "postgres", "postgresql", "sqlite", "mongodb", "redis", "memcached", "elasticsearch", "elastic", "cassandra",
  "content", "console", "directory", "manager", "panel", "admin", "login", "logout", "config", "configuration", "upload", "download", "view", "list", "index", "search", "read", "write", "text", "data", "utils", "utility", "api", "web", "app", "application", "site", "page", "portal", "dashboard", "interface", "module", "plugin", "component", "service", "client", "user", "account", "session", "token", "password", "credential", "key", "secret", "auth", "request", "response", "header", "body", "function", "script", "code", "execute", "command", "injection", "remote", "local", "arbitrary", "attacker", "unauth", "authenticated", "unauthenticated", "version", "versions", "prior", "before", "after", "multiple", "vulnerable", "vulnerability", "vulnerabilities", "security", "issue", "issues", "exploit", "exploits", "denial", "escalation", "disclosure", "exposure", "bypass", "override", "flaw", "bug", "error", "warning", "info", "information", "access", "control", "privilege", "leading", "lead", "allows", "affects", "affected",
  "powered", "power", "by", "software", "systems", "technologies", "solutions", "enterprise", "professional", "studio", "labs", "network", "networks", "cloud", "hosting", "platform", "framework", "library", "inc", "ltd", "llc", "corp", "co", "company", "free", "open", "source", "project", "wordpress", "joomla", "drupal", "magento", "shopify", "prestashop", "zencart", "opencart",
  "red", "hat", "magic", "hue", "get", "set", "use", "run", "top", "new",
  "server", "and", "or", "the", "a", "an", "for", "with", "via", "from", "into", "to", "of", "on", "in", "is", "are", "as", "at", "by", "it", "its", "this", "that", "these", "those", "mod", "proxy", "gateway", "adc", "not", "no", "yes", "up", "out",
  "domain", "check", "report", "reports", "system", "tool", "tools", "management", "monitor", "advanced", "basic", "standard", "lite", "pro", "plus", "main", "feature", "features", "options", "settings", "action", "actions", "type", "types", "name", "names", "value", "values", "field", "fields", "id", "key", "keys",
]);

function tokens(text: string): string[] {
  const out: string[] = [];
  for (const t of text.toLowerCase().split(/[^a-z0-9]+/)) {
    if (!t || t.length < 3) continue;
    if (/^\d+(\.\d+)*$/.test(t)) continue;
    if (GENERIC.has(t)) continue;
    out.push(t);
  }
  return out;
}

function firstMatch(txt: string, re: RegExp): string | null {
  const m = re.exec(txt);
  return m ? m[1].trim() : null;
}

function parseTemplate(text: string): CorpusEntry | null {
  const cve = firstMatch(text, /^id:\s*(\S+)/m);
  if (!cve || !cve.toUpperCase().startsWith("CVE-")) return null;
  const name = firstMatch(text, /^\s*name:\s*(.+)$/m) ?? cve;
  const severity = firstMatch(text, /^\s*severity:\s*(\w+)/m) ?? undefined;
  const epssStr = firstMatch(text, /^\s*epss-score:\s*([\d.]+)/m);
  const cwe = firstMatch(text, /^\s*cwe-id:\s*(CWE-\d+)/m) ?? undefined;
  let prod = name.split(/\s+-\s+|:\s+/, 1)[0].trim();
  prod = prod.replace(/[\s<>=~]+[vV]?[\d][\w.\-]*.*$/, "").trim();
  const kw = new Set(tokens(prod));
  for (const q of text.matchAll(/^\s*(?:fofa|shodan)-query:\s*(.+)$/gm)) {
    for (const m of q[1].matchAll(/(?:body|title|header|http\.html|html)\s*=\s*"([^"]+)"/g)) {
      for (const t of tokens(m[1])) kw.add(t);
    }
  }
  if (kw.size === 0) for (const t of tokens(name).slice(0, 3)) kw.add(t);
  const kwSorted = [...kw].sort().slice(0, 8);
  const match = kwSorted.length ? `\\b(?:${kwSorted.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b` : undefined;
  return {
    cve,
    name,
    product: prod,
    severity,
    epss: parseFloat(epssStr ?? "0") || 0,
    cwe,
    match,
  };
}

export function findTemplatesDir(): string | null {
  const candidates = [join(homedir(), "nuclei-templates"), join(homedir(), ".nuclei-templates"), "/root/nuclei-templates"];
  for (const c of candidates) if (existsSync(join(c, "http", "cves"))) return c;
  return null;
}

function loadLiveCorpus(): CorpusEntry[] {
  const dir = findTemplatesDir();
  if (!dir) return [];
  const out: CorpusEntry[] = [];
  const walk = (d: string) => {
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const name of entries) {
      const full = join(d, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(full);
      else if (name.endsWith(".yaml")) {
        try {
          const e = parseTemplate(readFileSync(full, "utf8"));
          if (e) out.push(e);
        } catch {
          /* skip unreadable */
        }
      }
    }
  };
  walk(join(dir, "http", "cves"));
  return out;
}

let cache: CorpusEntry[] | null = null;

export function invalidateCorpusCache(): void {
  cache = null;
}

/** The full CVE fingerprint corpus: live nuclei-templates when present,
 *  otherwise the bundled snapshot. */
export function loadCorpusEntries(): CorpusEntry[] {
  if (cache) return cache;
  const live = loadLiveCorpus();
  if (live.length > 0) {
    cache = live;
    return live;
  }
  try {
    const data = JSON.parse(readFileSync(join(ROOT, "intelligence", "cve-corpus.json"), "utf8")) as { cves?: Array<Record<string, unknown>> };
    cache = (data.cves ?? []).map((c) => ({
      cve: String(c.cve ?? ""),
      name: String(c.name ?? ""),
      product: String(c.product ?? ""),
      severity: typeof c.severity === "string" ? c.severity : undefined,
      epss: typeof c.epss === "number" ? c.epss : parseFloat(String(c.epss ?? "0")) || 0,
      cwe: typeof c.cwe === "string" ? c.cwe : undefined,
      match: typeof c.match === "string" ? c.match : undefined,
    }));
    return cache;
  } catch {
    return [];
  }
}

/** True when a live nuclei-templates tree is available (vs bundled snapshot). */
export function corpusSourceIsLive(): boolean {
  return findTemplatesDir() !== null;
}
