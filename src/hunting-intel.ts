/** Hunting intel — precision + prioritization signals.
 *
 *  Two deterministic, data-driven tools that make the "what to hunt" and "am I
 *  even looking at the real target" decisions concrete:
 *
 *   1. resolveCheck(host) — DNS SINKHOLE detection. Some ISPs / countries
 *      redirect whole categories of domains (gambling, adult, streaming) to a
 *      blocking/sinkhole page. If undetected, a scanner audits the sinkhole
 *      (a .gov / "blocked" warning page) instead of the real site. Compares the
 *      local resolver against public DNS (8.8.8.8 / 1.1.1.1) and probes the
 *      local IP for blocking-page content — the CONTENT is the signal, because
 *      a different IP set alone is normal for CDN/anycast.
 *
 *   2. watchlist() — the most-reported bug-bounty classes (CWE frequency) and
 *      high-value CVEs, each with payout range + a "saturated" flag, joined to
 *      a Blitz Strike detector pattern for grounding. Prioritize high-frequency,
 *      high-payout, NOT-yet-saturated classes; skip the saturated/low-value ones.
 */
import { execFileSync } from "node:child_process";
import { resolve4, Resolver } from "node:dns/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { patternLookup } from "./patterns.js";
import { loadCorpusEntries } from "./nuclei-corpus.js";

// Package-root-relative resolution (NOT process.cwd() — the MCP server may be
// launched from any directory via npx / the compiled binary).
const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");

// ---------------------------------------------------------------------------
// resolveCheck — DNS sinkhole / blocking-page detection
// ---------------------------------------------------------------------------

const BLOCKING_KEYWORDS =
  /internet positif|kominfo|\.go\.id\b|pemblokiran|ditutup|dilarang|akses dibatasi|blocked|restricted|illegal|advertencia|coljuegos|regulat|forbidden|this (site|website) has been (blocked|banned)/i;

/** Strict hostname guard — rejects anything with shell/URL metacharacters before
 *  the value ever reaches a subprocess or DNS resolver. */
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export function isValidHostname(host: string): boolean {
  return host.length <= 253 && HOSTNAME_RE.test(host);
}

/** Pure content check — does the body look like an ISP/country blocking page? */
export function isBlockingContent(text: string): boolean {
  return BLOCKING_KEYWORDS.test(text);
}

export interface ResolveCheckResult {
  host: string;
  local_ips: string[];
  public_ips: string[];
  sinkhole: boolean;
  verdict: string;
  evidence: string;
}

async function localResolve(host: string): Promise<string[]> {
  try { return await resolve4(host); } catch { return []; }
}

async function publicResolve(host: string): Promise<string[]> {
  const r = new Resolver();
  r.setServers(["8.8.8.8", "1.1.1.1"]);
  try { return await r.resolve4(host); } catch { return []; }
}

/** Probe `ip` for the real host (curl --resolve) and detect blocking-page content.
 *  Uses execFileSync (no shell) — host/ip are literal argv, never shell text. */
function probeBlockingPage(host: string, ip: string, timeoutMs = 8000): { probed: boolean; sinkhole: boolean; preview: string } {
  for (const port of ["443", "80"]) {
    const scheme = port === "443" ? "https" : "http";
    try {
      const out = execFileSync(
        "curl",
        ["-sk", "-m", "6", "--resolve", `${host}:${port}:${ip}`, `${scheme}://${host}/`],
        { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "ignore"] },
      );
      const preview = out.replace(/\s+/g, " ").trim().slice(0, 300);
      if (!preview) continue;
      return { probed: true, sinkhole: BLOCKING_KEYWORDS.test(preview), preview };
    } catch {
      /* port refused / timeout — try the next */
    }
  }
  return { probed: false, sinkhole: false, preview: "" };
}

export async function resolveCheck(host: string): Promise<ResolveCheckResult> {
  const clean = host.replace(/^https?:\/\//, "").split("/")[0];
  if (!isValidHostname(clean)) {
    return { host: clean, local_ips: [], public_ips: [], sinkhole: false, verdict: "invalid", evidence: "not a valid hostname — rejected before DNS/subprocess" };
  }
  const local = await localResolve(clean);
  const pub = await publicResolve(clean);

  if (local.length === 0 && pub.length === 0) {
    return { host: clean, local_ips: [], public_ips: [], sinkhole: false, verdict: "unresolvable", evidence: "no A record from local or public DNS" };
  }
  if (local.length === 0) {
    return { host: clean, local_ips: [], public_ips: pub, sinkhole: false, verdict: "local-unresolvable", evidence: "local resolver returned no A record; public DNS resolves. Use the public IP to reach the real target." };
  }

  const firstLocal = local[0];
  const probe = probeBlockingPage(clean, firstLocal);

  if (probe.sinkhole) {
    return {
      host: clean, local_ips: local, public_ips: pub, sinkhole: true,
      verdict: "sinkhole",
      evidence: `local IP ${firstLocal} serves a blocking/sinkhole page ("${probe.preview.slice(0, 120)}"). Audit the PUBLIC IP (${pub[0] ?? "n/a"}) instead — e.g. curl --resolve ${clean}:443:${pub[0]} https://${clean}/`,
    };
  }
  if (!probe.probed) {
    return { host: clean, local_ips: local, public_ips: pub, sinkhole: false, verdict: "inconclusive", evidence: "local IP did not respond on 443/80 — inconclusive; for sensitive niches prefer the public IP anyway." };
  }
  const ipDiff = new Set(local).size !== new Set(pub).size || !pub.every((ip) => local.includes(ip));
  return {
    host: clean, local_ips: local, public_ips: pub, sinkhole: false,
    verdict: ipDiff ? "clean-cdn" : "clean",
    evidence: ipDiff
      ? "local and public IPs differ but the local page shows no blocking content (normal for CDN/anycast/round-robin)."
      : "local resolution matches public DNS and shows no blocking content.",
  };
}

// ---------------------------------------------------------------------------
// watchlist — known CWE/CVE frequency + payout (prioritized, joined to patterns)
// ---------------------------------------------------------------------------

interface WatchlistEntry {
  cwe: string;
  name: string;
  rank: number;
  saturated: boolean;
  pattern: string | null;
  payout_min: number | null;
  payout_max: number | null;
  typical_payout: string;
  notes: string;
  grounded: boolean;
}

interface CveEntry {
  cve: string;
  name: string;
  product: string;
  class: string;
  epss?: number;
  reports?: number;
  fingerprint?: string;
  payout_hint?: string;
  match?: string;
  fixed_in?: string | null;
  version_key?: string | null;
  severity?: string;
}

export interface WatchlistResult {
  cwe_frequency: WatchlistEntry[];
  cve_watchlist: CveEntry[];
  recommendation: string;
}

function loadWatchlist(): { cwe_frequency: any[]; cve_watchlist: CveEntry[] } {
  const raw = readFileSync(join(ROOT, "intelligence", "watchlist.json"), "utf8");
  const data = JSON.parse(raw);
  return { cwe_frequency: data.cwe_frequency ?? [], cve_watchlist: data.cve_watchlist ?? [] };
}

/** Load the CVE corpus — live from nuclei-templates when present (auto-fresh
 *  after `nuclei -update-templates`), else the bundled snapshot. */
function loadCorpus(): CveEntry[] {
  return loadCorpusEntries().map((c) => ({
    cve: c.cve,
    name: c.name,
    product: c.product,
    class: "",
    epss: c.epss,
    reports: 0,
    fingerprint: c.product,
    match: c.match,
    fixed_in: null,
    version_key: null,
    severity: c.severity,
  }));
}

function fmtPayout(min: number | null, max: number | null): string {
  if (min == null || max == null) return "n/a";
  const f = (n: number): string => (n >= 1000 ? `$${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)}K` : `$${n}`);
  return `${f(min)}–${f(max)}`;
}

export function watchlist(): WatchlistResult {
  const { cwe_frequency, cve_watchlist } = loadWatchlist();
  const entries: WatchlistEntry[] = cwe_frequency.map((e) => {
    const pat = e.pattern ? patternLookup(e.pattern) : null;
    const payoutMin = e.payout_min ?? pat?.payout_min ?? null;
    const payoutMax = e.payout_max ?? pat?.payout_max ?? null;
    return {
      cwe: e.cwe,
      name: e.name,
      rank: e.rank,
      saturated: e.saturated,
      pattern: e.pattern ?? null,
      payout_min: payoutMin,
      payout_max: payoutMax,
      typical_payout: fmtPayout(payoutMin, payoutMax),
      notes: e.notes,
      grounded: pat != null,
    };
  }).sort((a, b) => a.rank - b.rank);

  const unsaturated = entries.filter((e) => !e.saturated);
  const topCve = cve_watchlist.filter((c) => (c.epss ?? 0) >= 0.8 || (c.reports ?? 0) >= 100).slice(0, 4).map((c) => c.cve).join(", ");
  const recommendation = `Prioritize the ${unsaturated.length} non-saturated classes (top: ${unsaturated.slice(0, 3).map((e) => e.cwe).join(", ")}) — high frequency + high payout + not yet saturated. Skip saturated/low-value classes (XSS/CSRF/open-redirect standalone) unless they chain into account takeover. FINGERPRINT FIRST: if the target stack matches a watchlist product (Next.js, Kibana, Langflow, Confluence/Jira, PAN-OS, Grafana), test that specific CVE — top EPSS/report CVEs: ${topCve}.`;

  return { cwe_frequency: entries, cve_watchlist, recommendation };
}

/** Simple semver comparison (numeric dot-separated; prerelease/build tags treated
 *  as 0). Returns true when `a` is strictly lower than `b`. */
export function semverLt(a: string, b: string): boolean {
  const pa = a.replace(/^v/, "").split(/[-+.]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.replace(/^v/, "").split(/[-+.]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

export interface DetectedVersion {
  product: string;
  version: string;
}

/** Fingerprint-first: match a set of detected techs (and the raw headers/body)
 *  against the CVE watchlist + the nuclei-derived CVE corpus — returns the
 *  specific CVEs to test when the target stack matches a known product. The
 *  hand-curated watchlist (with `fixed_in`/`version_key`) OVERRIDES a corpus
 *  entry of the same CVE; a detected version >= fixed_in is excluded as
 *  patched. Results are ranked by EPSS then severity and capped at 20. */
export function watchlistCveMatches(techs: string[], headers: Record<string, string> = {}, body: string = "", versions: DetectedVersion[] = [], max = 20): CveEntry[] {
  const { cve_watchlist } = loadWatchlist();
  const corpus = loadCorpus();
  const haystack = `${techs.join(" ")} ${Object.keys(headers).join(" ")} ${Object.values(headers).join(" ")} ${body}`.toLowerCase();

  // Merge: hand-curated entries take precedence over the corpus by CVE.
  const curated = new Map(cve_watchlist.map((c) => [c.cve, c]));
  const merged = [...corpus.filter((c) => !curated.has(c.cve)), ...cve_watchlist];

  const matched = merged.filter((c) => {
    const m = c.match;
    if (!m) return false;
    let ok = false;
    try {
      ok = new RegExp(m, "i").test(haystack);
    } catch {
      ok = false;
    }
    if (!ok) return false;
    const fixedIn = c.fixed_in;
    const vkey = c.version_key;
    if (fixedIn && vkey) {
      const v = versions.find((x) => x.product.toLowerCase().includes(vkey.toLowerCase()));
      if (v?.version && !semverLt(v.version, fixedIn)) return false;
    }
    return true;
  });

  const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  matched.sort((a, b) => {
    const ea = a.epss ?? 0;
    const eb = b.epss ?? 0;
    if (ea !== eb) return eb - ea;
    return (sevRank[a.severity ?? ""] ?? 9) - (sevRank[b.severity ?? ""] ?? 9);
  });

  return matched.slice(0, max);
}
