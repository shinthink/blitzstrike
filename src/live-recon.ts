/** Live reconnaissance — modular, intel-integrated.
 *
 * Extends `active.ts` (fingerprint + WAF + 18 hardcoded paths) into a real
 * recon pipeline. Each phase is PASIVE (fetch public pages / cert-transparency)
 * or ACTIVE (TCP port scan), and ACTIVE phases must only run when the caller
 * has already passed scope_check.
 *
 * Every phase cross-references the intelligence layer (techCorrelation,
 * portCorrelation, cveCorrelation, payloadLookup, templateLookup) and returns
 * `next_steps` directives so the driving MCP agent knows exactly what to do
 * after each result.
 */
import { detectWaf, techCorrelation, portCorrelation, payloadLookup, templateLookup, type WafDetection } from "./intel.js";
import { scanSinks, detectSourceLeak, type SinkHit } from "./sinks.js";
import { researchHeaders } from "./http.js";

const HTTP_TIMEOUT_MS = 20000;

/** Heuristic CDN check: true if the IP sits in a known CDN/proxy range (Cloudflare,
 * CloudFront, Fastly, Akamai, DDoS-Guard, Imperva). Non-CDN IPs are origin candidates. */
export function isLikelyCdn(ip: string): boolean {
  const o = ip.split(".").map((n) => parseInt(n, 10));
  if (o.length !== 4 || o.some((n) => Number.isNaN(n))) return true;
  const [a, b] = o;
  // Cloudflare
  if (a === 104 && b >= 16 && b <= 31) return true;
  if (a === 172 && (b === 64 || b === 65 || b === 66 || b === 67)) return true;
  if (a === 173 && b === 245) return true;
  if (a === 103 && (b === 21 || b === 22)) return true;
  if (a === 141 && b === 101) return true;
  if (a === 188 && b === 114) return true;
  if (a === 198 && b === 41) return true;
  // CloudFront
  if (a === 13 || a === 52 || a === 54) return true;
  // Fastly
  if (a === 151 && b === 101) return true;
  if (a === 199 && b === 27) return true;
  // Akamai / DDoS-Guard / Imperva (broad first-octet heuristics)
  if (a === 23 && (b === 32 || b === 192 || b === 216)) return true;
  if (a === 185 && (b >= 80 && b <= 89)) return true;
  if (a === 186 && b === 2) return true;
  return false;
}

async function httpGet(url: string, opts: { redirect?: "follow" | "manual" | "error" } = {}): Promise<{ status: number; headers: Record<string, string>; body: string; ok: boolean }> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: opts.redirect ?? "follow", headers: researchHeaders() });
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, body: body.slice(0, 500000), ok: res.ok };
  } catch (e) {
    return { status: 0, headers: {}, body: String(e), ok: false };
  } finally {
    clearTimeout(t);
  }
}

function normalizeTarget(target: string): string {
  let t = target.trim();
  if (!/^https?:\/\//i.test(t)) t = `https://${t}`;
  return t.replace(/\/+$/, "");
}

// ---------------------------------------------------------------------------
// Phase: crawler (passive) — extract links + endpoints from HTML / robots / sitemap
// ---------------------------------------------------------------------------

export interface CrawlResult {
  links: string[];
  scripts: string[];
  endpoints: string[];
  robots: string[];
  sitemap: string[];
  count: number;
}

export function crawlLinks(base: string, body: string): { links: string[]; scripts: string[] } {
  const links: string[] = [];
  const scripts: string[] = [];
  const hrefRe = /<a[^>]+href=["']([^"'#]+)["']/gi;
  const scriptRe = /<script[^>]+src=["']([^"'#]+)["']/gi;
  let m;
  while ((m = hrefRe.exec(body)) !== null) {
    let u = m[1];
    if (u.startsWith("/")) u = base + u;
    else if (!/^https?:\/\//i.test(u)) u = base + "/" + u;
    links.push(u);
  }
  while ((m = scriptRe.exec(body)) !== null) {
    let u = m[1];
    if (u.startsWith("/")) u = base + u;
    else if (!/^https?:\/\//i.test(u)) u = base + "/" + u;
    scripts.push(u);
  }
  return { links, scripts };
}

export async function fetchRobotsAndSitemap(base: string): Promise<{ robots: string[]; sitemap: string[] }> {
  const robots: string[] = [];
  const sitemap: string[] = [];
  const rob = await httpGet(`${base}/robots.txt`);
  if (rob.status === 200) {
    for (const line of rob.body.split("\n")) {
      const sm = line.match(/^Sitemap:\s*(.+)$/i);
      if (sm) sitemap.push(sm[1].trim());
      const allow = line.match(/^(?:Allow|Disallow):\s*(.+)$/i);
      if (allow && !allow[1].includes("*")) robots.push(base + allow[1].trim());
    }
  }
  // also try sitemap.xml directly
  const sm = await httpGet(`${base}/sitemap.xml`);
  if (sm.status === 200 && sm.body.includes("<loc>")) {
    const locRe = /<loc>([^<]+)<\/loc>/gi;
    let m;
    while ((m = locRe.exec(sm.body)) !== null) sitemap.push(m[1].trim());
  }
  return { robots, sitemap };
}

export function extractParams(urls: string[]): string[] {
  const params = new Set<string>();
  for (const u of urls) {
    try {
      const q = new URL(u).searchParams;
      for (const k of q.keys()) params.add(k);
    } catch { /* ignore malformed */ }
  }
  return [...params];
}

// ---------------------------------------------------------------------------
// Phase: subdomain enumeration (passive) — crt.sh cert transparency
// ---------------------------------------------------------------------------

export async function subdomainEnum(domain: string): Promise<{ subdomains: string[]; source: string }> {
  const out = new Set<string>();
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const r = await httpGet(url);
    if (r.status === 200 && r.body.startsWith("[")) {
      const data = JSON.parse(r.body);
      for (const entry of data) {
        for (const field of (entry.name_value ?? "").split("\n")) {
          const name = field.trim().toLowerCase();
          if (name && name.endsWith(domain.toLowerCase()) && !name.includes("*")) out.add(name);
        }
      }
    }
  } catch { /* crt.sh down — return empty */ }
  return { subdomains: [...out].sort(), source: "crt.sh (certificate transparency)" };
}

// ---------------------------------------------------------------------------
// Phase: Wayback Machine URL discovery (passive OSINT) — historical URLs
// ---------------------------------------------------------------------------

export async function waybackUrls(domain: string): Promise<{ urls: string[]; source: string }> {
  const out = new Set<string>();
  const url = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=10000`;
  // archive.org CDX is slow and aborts on redirect-follow; fetch directly with a
  // long timeout and no redirect following.
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 25000);
    const res = await fetch(url, { signal: controller.signal, redirect: "manual" });
    const body = await res.text();
    clearTimeout(t);
    if (body.startsWith("[[")) {
      const data = JSON.parse(body);
      for (let i = 1; i < data.length; i++) {
        const u = data[i]?.[0];
        if (u && typeof u === "string" && u.includes(domain)) out.add(u);
      }
    }
  } catch { /* archive.org down or timed out — return empty */ }
  return { urls: [...out].slice(0, 10000), source: "web.archive.org (Wayback CDX)" };
}

// ---------------------------------------------------------------------------
// Phase: DNS subdomain brute (passive) — resolve common prefixes
// ---------------------------------------------------------------------------

import { resolve4 } from "node:dns/promises";

const COMMON_SUBDOMAINS = [
  "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
  "app", "blog", "shop", "store", "cdn", "static", "assets", "img", "images",
  "secure", "vpn", "remote", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
  "dns", "db", "database", "mysql", "git", "gitlab", "jenkins", "ci", "jira",
  "wiki", "docs", "help", "support", "status", "monitor", "grafana", "kibana",
  "backup", "old", "beta", "demo", "sandbox", "internal", "intranet",
];

export async function dnsBrute(domain: string): Promise<{ found: Array<{ host: string; ips: string[] }>; source: string }> {
  const base = domain.toLowerCase();
  const seen = new Set<string>([base, "www." + base]);
  const hosts = COMMON_SUBDOMAINS.map((p) => `${p}.${base}`).filter((h) => !seen.has(h));
  const settled = await Promise.allSettled(hosts.map(async (host) => {
    try {
      const ips = await resolve4(host);
      return ips.length > 0 ? { host, ips } : null;
    } catch { return null; }
  }));
  const found: Array<{ host: string; ips: string[] }> = [];
  for (const r of settled) if (r.status === "fulfilled" && r.value) found.push(r.value);
  return { found, source: "DNS resolution (common subdomain prefixes)" };
}

// ---------------------------------------------------------------------------
// Phase: port scan (ACTIVE) — common TCP ports
// ---------------------------------------------------------------------------

import { connect } from "node:net";

const COMMON_PORTS: Array<[number, string]> = [
  [21, "ftp"], [22, "ssh"], [25, "smtp"], [53, "dns"], [80, "http"], [110, "pop3"],
  [135, "msrpc"], [139, "netbios"], [143, "imap"], [443, "https"], [445, "smb"],
  [993, "imaps"], [995, "pop3s"], [1433, "mssql"], [1521, "oracle"], [3306, "mysql"],
  [3389, "rdp"], [5432, "postgres"], [6379, "redis"], [8080, "http-alt"],
  [8443, "https-alt"], [9000, "app"], [9090, "app"], [9200, "elasticsearch"],
  [11211, "memcached"], [27017, "mongodb"],
];

function tcpProbe(host: string, port: number, timeout = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port, timeout });
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("timeout", () => { socket.destroy(); resolve(false); });
    socket.once("error", () => { socket.destroy(); resolve(false); });
  });
}

export async function scanPorts(host: string): Promise<Array<{ port: number; service: string; open: boolean; correlation?: Record<string, unknown> }>> {
  const settled = await Promise.allSettled(COMMON_PORTS.map(async ([port, service]) => {
    const open = await tcpProbe(host, port);
    if (open) {
      const corr = portCorrelation(port);
      return { port, service, open: true, correlation: corr };
    }
    return null;
  }));
  const out: Array<{ port: number; service: string; open: boolean; correlation?: Record<string, unknown> }> = [];
  for (const r of settled) if (r.status === "fulfilled" && r.value) out.push(r.value);
  return out;
}

// ---------------------------------------------------------------------------
// Phase: API discovery (passive) — swagger/openapi/graphql/actuator
// ---------------------------------------------------------------------------

const API_PATHS = [
  "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs", "/v2/api-docs",
  "/v3/api-docs", "/graphql", "/graphiql", "/actuator", "/actuator/health", "/actuator/env",
  "/api/swagger.json", "/docs", "/redoc",
];

export async function discoverApi(base: string): Promise<Array<{ path: string; status: number; body_size: number }>> {
  const settled = await Promise.allSettled(API_PATHS.map(async (p) => {
    const r = await httpGet(`${base}${p}`);
    // 200-299 = exposed; 401/403 = present but auth-gated; 404/0 = absent (skip).
    if (r.status >= 200 && r.status < 400) {
      return { path: p, status: r.status, body_size: r.body.length };
    }
    return null;
  }));
  const out: Array<{ path: string; status: number; body_size: number }> = [];
  for (const r of settled) if (r.status === "fulfilled" && r.value) out.push(r.value);
  return out;
}

// ---------------------------------------------------------------------------
// Phase: version extraction (passive) — server header + body version markers
// ---------------------------------------------------------------------------

export function extractVersion(headers: Record<string, string>, body: string): Array<{ product: string; version: string; evidence: string }> {
  const out: Array<{ product: string; version: string; evidence: string }> = [];
  const server = headers["server"] ?? headers["x-powered-by"] ?? "";
  // nginx / apache / microsoft-iis
  const serverVer = /^(nginx|apache|microsoft-iis|openresty|liteSpeed|caddy)\/?([0-9][0-9.\-]*)?/i.exec(server);
  if (serverVer) {
    out.push({ product: serverVer[1].toLowerCase(), version: serverVer[2] ?? "unknown", evidence: server });
  }
  // php version from x-powered-by
  const phpVer = /php\/([0-9][0-9.\-]*)/i.exec(server);
  if (phpVer) out.push({ product: "php", version: phpVer[1], evidence: server });
  // wordpress version (meta generator)
  const wpVer = /content="WordPress\s+([0-9][0-9.]*)/i.exec(body);
  if (wpVer) out.push({ product: "wordpress", version: wpVer[1], evidence: `meta generator: WordPress ${wpVer[1]}` });
  // joomla
  const joomlaVer = /Joomla!?\s*([0-9][0-9.]*)/i.exec(body);
  if (joomlaVer) out.push({ product: "joomla", version: joomlaVer[1], evidence: `body: Joomla ${joomlaVer[1]}` });
  // drupal
  const drupalVer = /Drupal\s+([0-9][0-9.]*)/i.exec(body);
  if (drupalVer) out.push({ product: "drupal", version: drupalVer[1], evidence: `body: Drupal ${drupalVer[1]}` });
  // x-powered-by generic
  const powered = headers["x-powered-by"] ?? "";
  if (powered && !out.some((o) => powered.includes(o.product))) {
    out.push({ product: powered.split("/")[0].toLowerCase(), version: powered.split("/")[1] ?? "unknown", evidence: powered });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Intel correlation + guidance
// ---------------------------------------------------------------------------

export function correlateIntel(
  techs: string[],
  versionList: Array<{ product: string; version: string }>,
  portList: Array<{ port: number; service: string }>,
): {
  tech: Array<Record<string, unknown>>;
  versions: Array<Record<string, unknown>>;
  ports: Array<Record<string, unknown>>;
} {
  const tech = techs.map((t) => ({ tech: t, ...techCorrelation(t) }));
  const versions = versionList.map((v) => ({
    product: v.product,
    version: v.version,
    correlation: techCorrelation(v.product),
    payload_lookup: payloadLookup(v.product),
    template_lookup: templateLookup(v.product, 5),
  }));
  const ports = portList.map((p) => ({ port: p.port, service: p.service, ...portCorrelation(p.port) }));
  return { tech, versions, ports };
}

// ---------------------------------------------------------------------------
// Full live recon (all passive phases + optional active)
// ---------------------------------------------------------------------------

export interface LiveReconResult {
  target: string;
  host: string;
  fingerprint: Record<string, unknown>;
  waf: WafDetection;
  tech: Record<string, unknown>;
  versions: Array<{ product: string; version: string; evidence: string }>;
  crawl: CrawlResult;
  params: string[];
  subdomains: string[];
  dns_findings: Array<{ host: string; ips: string[] }>;
  wayback_urls: string[];
  api_endpoints: Array<{ path: string; status: number }>;
  open_ports: Array<{ port: number; service: string }>;
  intel: Record<string, unknown>;
  next_steps: string[];
  source_leak: { detected: boolean; sinks: SinkHit[]; hint?: string };
  origin_exposed: Array<{ host: string; ip: string }>;
}

export async function liveRecon(target: string, includeActive = false): Promise<LiveReconResult> {
  const base = normalizeTarget(target);
  const host = (() => { try { return new URL(base).hostname; } catch { return target; } })();

  // 1. root fetch + fingerprint
  const root = await httpGet(base);
  const interestingHeaders: Record<string, string> = {};
  for (const k of ["server", "x-powered-by", "x-aspnet-version", "x-drupal-cache", "x-generator", "via", "x-cache", "cf-ray"]) {
    if (root.headers[k]) interestingHeaders[k] = root.headers[k];
  }
  const fingerprint = {
    status: root.status,
    title: (root.body.match(/<title[^>]*>([^<]+)<\/title>/i) ?? [])[1]?.trim().slice(0, 200) ?? "",
    server: root.headers["server"] ?? root.headers["x-powered-by"] ?? "",
    headers: interestingHeaders,
    body_size: root.body.length,
  };

  // 2. WAF
  const waf = detectWaf(root.headers, root.body);

  // 3. tech + version
  const techSig: Array<[RegExp, string]> = [
    [/wp-content|wp-includes|wp-json/i, "wordpress"], [/wp-login\.php|wp-admin/i, "wordpress"],
    [/powered by joomla|com_content/i, "joomla"], [/laravel|_token|csrf-token/i, "laravel"],
    [/react|__NEXT_DATA__|next\/static/i, "nextjs"], [/angular|ng-version/i, "angular"],
    [/vue|__vue__|v-data/i, "vue"], [/django|csrftoken|__debug__/i, "django"],
    [/ruby on rails|rails/i, "rails"], [/asp\.net|__VIEWSTATE|__EVENTVALIDATION/i, "aspnet"],
    [/phpBB|phpbb/i, "phpbb"], [/mybb|mybb/i, "mybb"], [/drupal|Drupal\.settings/i, "drupal"],
    [/magento|Mage\./i, "magento"], [/shopify|cdn\.shopify/i, "shopify"],
    [/grafana|kibana|elastic/i, "grafana-kibana"], [/node\.js|express/i, "nodejs"],
    [/flask|werkzeug/i, "flask"], [/spring|actuator/i, "spring"],
  ];
  const techs = [...new Set(techSig.filter(([re]) => re.test(root.body)).map(([, t]) => t))];
  const versions = extractVersion(root.headers, root.body);

  // 4. crawler + robots + sitemap
  const { links, scripts } = crawlLinks(base, root.body);
  const { robots, sitemap } = await fetchRobotsAndSitemap(base);
  const allUrls = [...links, ...scripts, ...robots, ...sitemap];
  const crawl: CrawlResult = { links, scripts, endpoints: [...new Set(allUrls)], robots, sitemap, count: allUrls.length };
  const params = extractParams(allUrls);

  // 5-6. Passive recon phases — independent + latency-bound, run in PARALLEL.
  const [subRes, dnsRes, waybackRes, apiRes] = await Promise.all([
    subdomainEnum(host),
    dnsBrute(host),
    waybackUrls(host),
    discoverApi(base),
  ]);
  const subdomains = subRes.subdomains;
  const dnsFindings = dnsRes.found;
  const wayback = waybackRes.urls;
  const apiEndpoints = apiRes.map(({ path, status }) => ({ path, status }));

  // Origin-exposure flag — a subdomain resolving to a non-CDN IP (not Cloudflare/
  // CloudFront/Fastly) is a candidate for direct-to-origin bypass (WAF evaporates).
  const originExposed = dnsFindings
    .flatMap((d) => d.ips.map((ip) => ({ host: d.host, ip })))
    .filter((x) => !isLikelyCdn(x.ip));

  // 7. ports (ACTIVE)
  let openPorts: Array<{ port: number; service: string }> = [];
  if (includeActive && root.status > 0) {
    const scan = await scanPorts(host);
    openPorts = scan.map(({ port, service }) => ({ port, service }));
  }

  // 8. intel correlation
  const intel = correlateIntel(techs, versions, openPorts);

  // 9. next_steps
  const nextSteps: string[] = [];
  if (waf.detected) nextSteps.push(`WAF detected (${waf.wafs?.map((w) => w.waf).join(", ")}) — consult detect_waf + WAF bypass playbook before exploitation.`);
  for (const t of techs) {
    const c = techCorrelation(t);
    if (c.found) nextSteps.push(`Tech '${t}' maps to known vuln classes — read tech_correlation('${t}') and fetch nuclei templates with template_lookup('${t}').`);
  }
  for (const v of versions) {
    nextSteps.push(`Version ${v.product}/${v.version} detected — check cve_correlation + nvd_lookup for known CVEs affecting ${v.product} ${v.version}.`);
  }
  if (crawl.endpoints.length > 0) nextSteps.push(`Found ${crawl.endpoints.length} endpoints — feed them to taint_file/blitz_scan for source analysis, or strike_verify for live validation.`);
  if (params.length > 0) nextSteps.push(`Discovered input params: ${params.join(", ")} — these are attack-surface entry points; fuzz them with payload_lookup after scope confirms.`);
  if (subdomains.length > 0) nextSteps.push(`Found ${subdomains.length} subdomains — each is a separate scope surface; enumerate further with fofa_search.`);
  if (dnsFindings.length > 0) nextSteps.push(`DNS-resolved ${dnsFindings.length} hosts (${dnsFindings.map((d) => d.host).slice(0, 50).join(", ")}${dnsFindings.length > 50 ? "…" : ""}) — each is a live subdomain to recon.`);
  if (wayback.length > 0) nextSteps.push(`Wayback Machine surfaced ${wayback.length} historical URLs — mine them for hidden endpoints, old params, and forgotten pages; feed to taint_file/blitz_scan.`);
  if (openPorts.length > 0) nextSteps.push(`Open ports: ${openPorts.map((p) => `${p.port}/${p.service}`).join(", ")} — map services via port_correlation and probe each with the relevant tool manual.`);
  if (apiEndpoints.length > 0) nextSteps.push(`API endpoints exposed (${apiEndpoints.map((e) => e.path).join(", ")} ) — audit them with api-security playbook; check for BOLA/IDOR/auth gaps.`);
  if (originExposed.length > 0) nextSteps.push(`Origin-exposure: ${originExposed.length} host/IP pairs resolve to NON-CDN addresses (${originExposed.slice(0, 8).map((x) => `${x.host}→${x.ip}`).join(", ")}…) — retest direct-to-origin with --resolve + correct Host/SNI; the CDN/WAF layer evaporates.`);
  if (nextSteps.length === 0) nextSteps.push("Nothing exposed on the surface — try subdomain enumeration, port scan (active), or request source access for EAGLE-EYE analysis.");
  nextSteps.push("Every confirmed finding: record with finding_create, attach confidence_score, redact secrets. A hit is a hypothesis until verified.");

  return {
    target: base,
    host,
    fingerprint,
    waf,
    tech: { detected: techs, server: fingerprint.server },
    versions,
    crawl,
    params,
    subdomains,
    dns_findings: dnsFindings,
    wayback_urls: wayback,
    api_endpoints: apiEndpoints,
    open_ports: openPorts,
    intel,
    next_steps: nextSteps,
    origin_exposed: originExposed,
    source_leak: detectSourceLeak(root.body)
      ? {
          detected: true,
          sinks: scanSinks(root.body),
          hint: "The response leaks source/traceback. scan_leaked_source can re-scan any other leaked page; enumerate each sink (RCE/secret first) and exploit it.",
        }
      : { detected: false, sinks: [] },
  };
}
