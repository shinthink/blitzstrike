/** STRIKE recon module — FOFA + NVD lookups (network-bound).
 *
 * Credentials are read from environment variables, never hardcoded:
 *   FOFA_EMAIL, FOFA_KEY
 */

const TIMEOUT_MS = 25000;

async function httpJson<T = Record<string, unknown>>(url: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal, redirect: "follow" });
    const text = await res.text();
    try {
      return JSON.parse(text) as T;
    } catch {
      return { __http_error: `non-JSON response (HTTP ${res.status})`, __body: text.slice(0, 400) } as unknown as T;
    }
  } finally {
    clearTimeout(t);
  }
}

interface NvdDescription {
  lang?: string;
  value?: string;
}

interface NvdMetricData {
  cvssData?: { baseScore?: number; vectorString?: string };
}

interface NvdCve {
  id?: string;
  descriptions?: NvdDescription[];
  metrics?: Record<string, NvdMetricData[]>;
  published?: string;
  lastModified?: string;
  references?: Array<{ url?: string }>;
}

interface NvdResponse {
  vulnerabilities?: Array<{ cve?: NvdCve }>;
  __http_error?: string;
  __body?: string;
}

interface FofaResponse {
  error?: string;
  errmsg?: string;
  results?: unknown[];
  __http_error?: string;
  __body?: string;
}

export async function fofaSearch(
  query: string,
  size = 20,
  fields = "host,ip,port,protocol,title,server",
): Promise<Record<string, unknown>> {
  const email = process.env.FOFA_EMAIL ?? "";
  const key = process.env.FOFA_KEY ?? "";
  if (!email || !key) {
    return { error: "FOFA_EMAIL/FOFA_KEY env vars not set" };
  }

  const qbase64 = Buffer.from(query).toString("base64");
  const url = "https://fofa.info/api/v1/search/all";
  const params = new URLSearchParams({
    key,
    email,
    qbase64,
    size: String(Math.min(size, 100)),
    fields,
  });

  const data = await httpJson<FofaResponse>(`${url}?${params.toString()}`);
  if (data.__http_error) return data as unknown as Record<string, unknown>;
  if (data.error) {
    return { error: String(data.error).slice(0, 500), errmsg: String(data.errmsg ?? "").slice(0, 500) };
  }
  const results = data.results ?? [];
  return { query, size: results.length, results };
}

export async function nvdLookup(cveId: string): Promise<Record<string, unknown>> {
  let cid = cveId.trim().toUpperCase();
  if (!cid.startsWith("CVE-")) cid = `CVE-${cid}`;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cid)}`;

  const data = await httpJson<NvdResponse>(url);
  if (data.__http_error) return data as unknown as Record<string, unknown>;

  const vulns = data.vulnerabilities ?? [];
  if (vulns.length === 0) return { cve: cid, found: false };

  const cve = vulns[0].cve ?? {};
  const descriptions = cve.descriptions ?? [];
  const desc = descriptions.find((d) => d.lang === "en")?.value ?? "";
  const metrics = cve.metrics ?? {};

  let score: unknown = null;
  let vector: unknown = null;
  for (const group of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = metrics[group] ?? [];
    if (list.length > 0) {
      const cd = list[0].cvssData ?? {};
      score = cd.baseScore ?? null;
      vector = cd.vectorString ?? null;
      break;
    }
  }

  return {
    cve: cve.id,
    found: true,
    description: String(desc).slice(0, 2000),
    cvss_score: score,
    cvss_vector: vector,
    published: cve.published,
    lastModified: cve.lastModified,
    references: (cve.references ?? []).slice(0, 8).map((r) => r.url),
  };
}
