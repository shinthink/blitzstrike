/** Broken-link hijacking detector — enumerate outbound references and flag
 *  domains that are EXPIRED / registrable (a distinct takeover class from
 *  subdomain_takeover: this is a fully-expired registrable domain, not a
 *  dangling CNAME to a claimable service).
 *
 *  Derived, not hardcoded: the verdict comes from live DNS + RDAP (the
 *  authoritative registration-status protocol), never from a static list.
 */
import { resolve4 } from "node:dns/promises";
import { researchHeaders } from "./http.js";

export interface ClaimableDomain {
  domain: string;
  status: string;
  claimable: boolean;
  evidence: string;
  source: string; // where the reference was seen (src/href/js-url)
}

export interface BrokenLinkResult {
  target: string;
  base_host: string;
  outbound_hosts: number;
  checked: number;
  claimable: ClaimableDomain[];
  inconclusive: string[];
}

/** Normalize a URL to its hostname (lowercased, no www., no port). */
export function hostFromUrl(u: string): string | null {
  try {
    const h = new URL(u.startsWith("//") ? `https:${u}` : u).hostname.toLowerCase();
    return h || null;
  } catch {
    return null;
  }
}

/** Always-alive infrastructure/CDN domains we skip (they never expire, so an
 *  RDAP check is wasted). Everything else gets checked. */
const ALWAYS_ALIVE = new Set([
  "googleapis.com", "gstatic.com", "google.com", "googletagmanager.com", "google-analytics.com",
  "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
  "bootstrapcdn.com", "jquery.com", "fontawesome.com", "stackpathcdn.com",
  "w3.org", "schema.org", "github.com", "github.io", "npmjs.com", "nodejs.org",
  "microsoft.com", "azureedge.net", "azure.com", "akamai.net", "akamaized.net", "amazonaws.com", "amazon.com", "cloudfront.net",
  "youtube.com", "youtu.be", "instagram.com", "facebook.com", "fbcdn.net", "twitter.com", "x.com", "tiktok.com", "pinterest.com", "linkedin.com",
  "apple.com", "mozilla.org", "gravatar.com", "twimg.com", "g.co", "goo.gl", "bit.ly", "tinyurl.com",
  "paypal.com", "stripe.com", "shopify.com", "wordpress.org", "wp.com",
]);

/** Extract unique outbound hostnames (src/href + inline JS URLs), excluding the
 *  base host (and its subdomains) and always-alive infrastructure. */
export function extractOutboundHosts(html: string, baseHost: string): string[] {
  const hosts = new Set<string>();
  for (const m of html.matchAll(/(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    const h = hostFromUrl(m[1]);
    if (h) hosts.add(h);
  }
  for (const m of html.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
    hosts.add(m[1].toLowerCase());
  }
  const base = baseHost.toLowerCase().replace(/^www\./, "");
  const out = [...hosts].filter((h) => {
    const lh = h.toLowerCase().replace(/^www\./, "");
    if (lh === base || lh.endsWith(`.${base}`)) return false;
    if (ALWAYS_ALIVE.has(lh)) return false;
    for (const s of ALWAYS_ALIVE) if (lh.endsWith(`.${s}`)) return false;
    return true;
  });
  return [...new Set(out)].sort();
}

/** Live status for one domain: DNS resolution + RDAP registration status. */
export async function checkDomainStatus(domain: string): Promise<{ status: string; claimable: boolean; evidence: string }> {
  let resolved = true;
  try {
    await resolve4(domain);
  } catch {
    resolved = false;
  }
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: AbortSignal.timeout(7000),
      headers: { accept: "application/json" },
    });
    if (res.status === 404) {
      return { status: "unregistered", claimable: true, evidence: "RDAP 404 — domain not registered, registrable now" };
    }
    const data = (await res.json()) as { status?: string[] };
    const statuses = data.status ?? [];
    if (statuses.includes("pendingDelete") || statuses.includes("redemptionPeriod")) {
      return { status: statuses.join(","), claimable: true, evidence: `RDAP ${statuses.join(",")} — in the drop cycle, registrable soon` };
    }
    if (statuses.length > 0) {
      return { status: statuses.join(","), claimable: false, evidence: `RDAP ${statuses.join(",")} — still registered${resolved ? "" : " (held, no DNS)"}` };
    }
    return { status: resolved ? "resolved" : "nxdomain", claimable: false, evidence: "RDAP returned no status (inconclusive)" };
  } catch {
    return { status: resolved ? "resolved" : "nxdomain", claimable: false, evidence: resolved ? "RDAP lookup failed — cannot confirm registration status" : "NXDOMAIN + RDAP lookup failed (inconclusive)" };
  }
}

export async function brokenLinkScan(url: string, maxHosts = 30): Promise<BrokenLinkResult> {
  const base = url.startsWith("http") ? url : `https://${url}`;
  const baseHost = (() => {
    try {
      return new URL(base).hostname;
    } catch {
      return url;
    }
  })();

  let html = "";
  try {
    const res = await fetch(base, { signal: AbortSignal.timeout(15000), redirect: "follow", headers: researchHeaders() });
    html = (await res.text()).slice(0, 1_000_000);
  } catch {
    return { target: base, base_host: baseHost, outbound_hosts: 0, checked: 0, claimable: [], inconclusive: [] };
  }

  const hosts = extractOutboundHosts(html, baseHost).slice(0, maxHosts);
  const claimable: ClaimableDomain[] = [];
  const inconclusive: string[] = [];

  // Check in small concurrent batches (RDAP is rate-limited).
  for (let i = 0; i < hosts.length; i += 5) {
    const batch = hosts.slice(i, i + 5);
    const results = await Promise.all(
      batch.map(async (h) => {
        const r = await checkDomainStatus(h);
        return { domain: h, ...r };
      }),
    );
    for (const r of results) {
      if (r.claimable) claimable.push({ domain: r.domain, status: r.status, claimable: true, evidence: r.evidence, source: "outbound-reference" });
      else if (r.status === "nxdomain") inconclusive.push(r.domain);
    }
  }

  return {
    target: base,
    base_host: baseHost,
    outbound_hosts: hosts.length,
    checked: hosts.length,
    claimable,
    inconclusive,
  };
}
