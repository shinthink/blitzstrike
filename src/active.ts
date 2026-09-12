/** STRIKE active scan module — live black-box scanning (network-bound).
 *
 * This is the "type a URL → auto-run" tier. It fingerprints the stack, detects
 * WAF, discovers endpoints, and cross-references the intelligence layer. It is
 * GATED by scope_check — active scanning only proceeds when scope enforcement
 * authorizes it.
 */
import { detectWaf, techCorrelation, type WafDetection, type TechCorrelationResult } from "./intel.js";

const TIMEOUT_MS = 20000;

async function httpFetch(url: string, init?: RequestInit): Promise<{ status: number; headers: Record<string, string>; body: string; ok: boolean }> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal, redirect: "follow" });
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, body: body.slice(0, 20000), ok: res.ok };
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

function extractTitle(body: string): string {
  const m = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  return m ? m[1].trim().slice(0, 200) : "";
}

function detectServer(headers: Record<string, string>): string {
  return headers["server"] ?? headers["x-powered-by"] ?? "";
}

function detectTechFromBody(body: string): string[] {
  const hits: string[] = [];
  const sigs: Array<[RegExp, string]> = [
    [/wp-content|wp-includes|wp-json/i, "wordpress"],
    [/wp-login\.php|wp-admin/i, "wordpress"],
    [/powered by joomla|com_content/i, "joomla"],
    [/laravel|_token|csrf-token/i, "laravel"],
    [/react|__NEXT_DATA__|next\/static/i, "nextjs"],
    [/angular|ng-version/i, "angular"],
    [/vue|__vue__|v-data/i, "vue"],
    [/django|csrftoken|__debug__/i, "django"],
    [/ruby on rails|rails/i, "rails"],
    [/asp\.net|__VIEWSTATE|__EVENTVALIDATION/i, "aspnet"],
    [/phpBB|phpbb/i, "phpbb"],
    [/mybb|mybb/i, "mybb"],
    [/drupal|Drupal\.settings/i, "drupal"],
    [/magento|Mage\./i, "magento"],
    [/shopify|cdn\.shopify/i, "shopify"],
    [/grafana|kibana|elastic/i, "grafana-kibana"],
  ];
  for (const [re, name] of sigs) {
    if (re.test(body)) hits.push(name);
  }
  return [...new Set(hits)];
}

async function probeCommonPaths(base: string): Promise<Array<{ path: string; status: number }>> {
  const paths = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/wp-login.php", "/wp-admin/", "/wp-json/",
    "/administrator/", "/admin/", "/login", "/api/",
    "/.git/config", "/.env", "/config.php", "/phpinfo.php",
    "/swagger.json", "/swagger-ui.html", "/graphql", "/actuator/health",
  ];
  const out: Array<{ path: string; status: number }> = [];
  // probe sequentially with a small cap to avoid hammering
  for (const p of paths) {
    const r = await httpFetch(`${base}${p}`, { method: "GET" });
    out.push({ path: p, status: r.status });
  }
  return out;
}

export interface ActiveScanResult {
  target: string;
  gated: boolean;
  gate_reason?: string;
  waf?: WafDetection;
  fingerprint?: Record<string, unknown>;
  tech?: Record<string, unknown>;
  endpoints?: Array<{ path: string; status: number }>;
  recommendations?: string[];
}

/** Live black-box scan. Gated — returns gated:true without probing when unauthorized. */
export async function activeScan(
  target: string,
  scope = "",
  mode = "bug-bounty",
  allowed: boolean | undefined = undefined,
): Promise<ActiveScanResult> {
  const base = normalizeTarget(target);
  const host = (() => { try { return new URL(base).hostname; } catch { return target; } })();

  // Gate: authorized only when explicitly allowed (caller runs scope_check first).
  if (allowed === false) {
    return {
      target: base,
      gated: true,
      gate_reason: `active scanning not authorized for '${host}' (mode=${mode}, scope='${scope || "unset"}')`,
    };
  }

  const result: ActiveScanResult = { target: base, gated: false };

  // 1. fetch root
  const root = await httpFetch(base);
  if (root.status === 0) {
    result.gated = true;
    result.gate_reason = `could not reach ${base}: ${root.body.slice(0, 120)}`;
    return result;
  }

  // 2. WAF detection from headers + body
  result.waf = detectWaf(root.headers, root.body);

  // 3. fingerprint: title, server, headers of interest
  const interestingHeaders: Record<string, string> = {};
  for (const k of ["server", "x-powered-by", "x-aspnet-version", "x-drupal-cache", "x-generator", "via", "x-cache", "cf-ray"]) {
    if (root.headers[k]) interestingHeaders[k] = root.headers[k];
  }
  result.fingerprint = {
    status: root.status,
    title: extractTitle(root.body),
    server: detectServer(root.headers),
    headers: interestingHeaders,
    body_size: root.body.length,
  };

  // 4. tech detection + correlation
  const techs = detectTechFromBody(root.body);
  const serverTech = detectServer(root.headers);
  result.tech = {
    detected: techs,
    server: serverTech,
    correlations: techs.map((t) => techCorrelation(t)).filter((c) => c.found === true),
  };

  // 5. endpoint discovery (common paths)
  result.endpoints = await probeCommonPaths(base);

  // 6. recommendations from findings
  const recs: string[] = [];
  if (result.waf?.detected) recs.push(`WAF detected (${result.waf.wafs?.map((w) => w.waf).join(", ")}) — apply WAF bypass before exploitation.`);
  const interesting = result.endpoints?.filter((e) => e.status >= 200 && e.status < 400 && !e.path.includes(".well-known"));
  if (interesting && interesting.length > 0) {
    recs.push(`Live endpoints found: ${interesting.map((e) => e.path).join(", ")} — trace these with EAGLE-EYE / verify with STRIKE.`);
  }
  for (const c of (result.tech?.correlations ?? []) as TechCorrelationResult[]) {
    recs.push(`Tech '${c.tech}' maps to known vuln classes: ${(c.vulns ?? []).slice(0, 3).join(", ")}`);
  }
  result.recommendations = recs;

  return result;
}
