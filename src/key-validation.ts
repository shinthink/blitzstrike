/** Leaked-key validation — prove a recovered credential is still ACTIVE on the
 *  live API with a READ-ONLY differential test: the same endpoint is fetched
 *  without the key (expect 401/403) and with the key (expect 200). No mutating
 *  request is ever sent. A 401-without / 200-with pair is proof of auth bypass.
 *
 *  Mirrors the evidence-first doctrine: the "without key" request is the negative
 *  control, the "with key" request is the marker — only the CONTRAST is proof.
 */
export interface KeyValidationInput {
  /** Raw secret value to test (skip blob fetch). */
  key?: string;
  /** Or: a raw-blob URL (e.g. a forge raw/commit/<sha>^/<path>) to fetch + parse the key from. */
  blobUrl?: string;
  /** The variable name to parse from the blob (e.g. SECRET_KEY). */
  varName?: string;
  /** Live API base URL. */
  apiBase: string;
  /** Read-only GET endpoints to probe (default ["/items"]). */
  endpoints?: string[];
  /** Header value template, e.g. "Bearer {value}" (default). */
  scheme?: string;
  /** Header name (default "Authorization"). */
  header?: string;
}

interface EndpointResult {
  endpoint: string;
  no_auth: number | null;
  with_key: number | null;
  records: number | null;
  verdict: "BYPASS" | "-" | "ERROR";
  error?: string;
}

function parseValueFromBlob(text: string, varName: string): string {
  const re = new RegExp(`${varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[=:]\\s*["']?([^"'\\n]+)`);
  const m = text.match(re);
  if (!m) throw new Error(`variable ${varName} not found in blob`);
  return m[1].trim();
}

async function httpGet(url: string, headers: Record<string, string>): Promise<{ status: number | null; body: string }> {
  try {
    const res = await fetch(url, { headers, redirect: "follow" });
    return { status: res.status, body: await res.text() };
  } catch (e) {
    return { status: null, body: String(e) };
  }
}

/** Differential leaked-key validation. Returns per-endpoint no-auth/with-key pairs
 *  + a `proven` flag when a 401/403-without → 200-with contrast was observed. */
export async function validateLeakedKey(input: KeyValidationInput): Promise<Record<string, unknown>> {
  const endpoints = input.endpoints ?? ["/items"];
  const scheme = input.scheme ?? "Bearer {value}";
  const header = input.header ?? "Authorization";
  let key = input.key ?? "";

  // Resolve the key: either directly, or by fetching + parsing a blob URL.
  if (!key && input.blobUrl) {
    const blobRes = await httpGet(input.blobUrl, { "User-Agent": "Mozilla/5.0 (recon-agent)" });
    if (blobRes.status !== 200) {
      return { ok: false, error: `blob fetch failed (HTTP ${blobRes.status}) — leak gone, privatized, or wrong sha`, step: "blob_fetch" };
    }
    try {
      key = parseValueFromBlob(blobRes.body, input.varName ?? "SECRET_KEY");
    } catch (e) {
      return { ok: false, error: String(e), step: "parse" };
    }
  }
  if (!key) {
    return { ok: false, error: "no key provided and no blobUrl to recover one from", step: "key" };
  }

  const authHeader = { [header]: scheme.replace("{value}", key) };
  const results: EndpointResult[] = [];
  let proven = false;

  for (const ep of endpoints) {
    const url = input.apiBase.replace(/\/$/, "") + (ep.startsWith("/") ? ep : "/" + ep);
    const r0 = await httpGet(url, { "User-Agent": "Mozilla/5.0 (recon-agent)" });
    const r1 = await httpGet(url, { "User-Agent": "Mozilla/5.0 (recon-agent)", ...authHeader });

    let verdict: EndpointResult["verdict"] = "-";
    if (r0.status === null || r1.status === null) verdict = "ERROR";
    else if ((r0.status === 401 || r0.status === 403) && r1.status === 200) { verdict = "BYPASS"; proven = true; }

    let records: number | null = null;
    if (r1.status === 200) {
      try { records = (JSON.parse(r1.body).data ?? []).length; } catch { records = null; }
    }

    results.push({
      endpoint: ep,
      no_auth: r0.status,
      with_key: r1.status,
      records,
      verdict,
      error: verdict === "ERROR" ? (r0.status === null ? r0.body : r1.body) : undefined,
    });
  }

  return {
    ok: true,
    proven,
    key_len: key.length,
    header,
    scheme,
    results,
    verdict: proven
      ? "AUTH BYPASS PROVEN — leaked credential valid on live system (read-only)"
      : "not proven — rotated? different header scheme? check manually",
  };
}
