/** `nuclei_scan` — fingerprint-driven full DAST pass.
 *
 *  The missing piece between "suggest a CVE" (fingerprint-first) and
 *  "confirm one CVE" (cve_verify): run the WHOLE relevant nuclei template set
 *  against a live target in one command. It fingerprints the stack (or uses the
 *  tech you pass), selects the fingerprint-matched CVE templates + (in broad
 *  mode) the tech-tag templates, runs nuclei rate-limited, and returns the
 *  deduped, severity-ranked findings. Findings are still HINTS — verify each
 *  before it enters a report.
 */
import { execFileSync } from "node:child_process";
import { detectTech, extractVersion } from "./live-recon.js";
import { watchlistCveMatches } from "./hunting-intel.js";

function normalizeTag(tech: string): string {
  return tech.toLowerCase().replace(/[^a-z0-9.-]/g, "").replace(/^\.+|\.+$/g, "");
}

async function fetchTarget(target: string): Promise<{ headers: Record<string, string>; body: string }> {
  const res = await fetch(target, { redirect: "follow", headers: { "User-Agent": "Mozilla/5.0 (compatible; BlitzStrike/2.4)" } });
  const body = await res.text();
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });
  return { headers, body };
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

export interface NucleiFinding {
  template_id: string;
  name: string;
  severity: string;
  matched_at: string;
  type?: string;
}

export interface NucleiScanResult {
  status: "ok" | "error";
  message?: string;
  target: string;
  techs: string[];
  matched_cves: string[];
  templates_ran: number;
  findings: NucleiFinding[];
}

export async function nucleiScan(opts: {
  target: string;
  tech?: string[];
  tags?: string[];
  severity?: string[];
  broad?: boolean;
  max?: number;
}): Promise<NucleiScanResult> {
  const target = opts.target;
  if (!/^https?:\/\//i.test(target)) {
    return { status: "error", message: "target must be an http(s) URL", target, techs: [], matched_cves: [], templates_ran: 0, findings: [] };
  }

  // Fingerprint (unless tech + tags were provided)
  let techs = opts.tech ?? [];
  let headers: Record<string, string> = {};
  let body = "";
  const needFp = techs.length === 0 && !(opts.tags && opts.tags.length);
  if (needFp) {
    try {
      ({ headers, body } = await fetchTarget(target));
    } catch {
      /* fingerprint fetch failed — continue with empty */
    }
  }
  if (techs.length === 0 && needFp) techs = detectTech(headers, body);
  const versions = needFp ? extractVersion(headers, body) : [];
  const matchedCves = needFp || opts.tech ? watchlistCveMatches(techs, headers, body, versions) : [];
  const cveIds = matchedCves.map((c) => c.cve);

  const severity = (opts.severity ?? ["critical", "high", "medium"]).join(",");
  const args = ["-u", target, "-jsonl", "-silent", "-no-color", "-timeout", "10", "-rate-limit", "150", "-severity", severity];

  if (cveIds.length > 0) args.push("-id", cveIds.join(","));
  if (opts.broad || (opts.tags && opts.tags.length > 0)) {
    const tags = opts.tags ?? techs.map(normalizeTag).filter(Boolean);
    if (tags.length > 0) args.push("-tags", tags.join(","));
  }

  let out: string;
  try {
    out = execFileSync("nuclei", args, { timeout: 300000, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  } catch (e) {
    const err = e as { stderr?: string; message?: string; code?: string };
    if (err.code === "ENOENT") {
      return { status: "error", message: "nuclei not installed (run blitzstrike install-tools)", target, techs, matched_cves: cveIds, templates_ran: 0, findings: [] };
    }
    return { status: "error", message: String(err.stderr ?? err.message ?? e), target, techs, matched_cves: cveIds, templates_ran: 0, findings: [] };
  }

  const findings: NucleiFinding[] = [];
  const seen = new Set<string>();
  for (const line of out.trim().split("\n")) {
    if (!line) continue;
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(line);
    } catch {
      continue;
    }
    const info = (m.info ?? {}) as Record<string, unknown>;
    const tid = String(m["template-id"] ?? "");
    if (!tid || seen.has(tid)) continue;
    seen.add(tid);
    findings.push({
      template_id: tid,
      name: String(info.name ?? tid),
      severity: String(info.severity ?? "unknown"),
      matched_at: String(m["matched-at"] ?? ""),
      type: typeof m.type === "string" ? m.type : undefined,
    });
  }

  findings.sort((a, b) => (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5));
  const max = opts.max ?? 50;
  return {
    status: "ok",
    target,
    techs,
    matched_cves: cveIds,
    templates_ran: cveIds.length + (opts.broad || (opts.tags && opts.tags.length) ? 1 : 0),
    findings: findings.slice(0, max),
  };
}
