/** Live HTTP traffic recorder — the automatic evidence ledger.
 *
 * When Blitz makes a request against a target, the actual request/response pair
 * is captured here — redacted, integrity-tagged (SHA-256), and session-scoped —
 * so that evidence can be grounded against REAL traffic instead of a model's
 * recollection. This is the backbone for the `verify_evidence` grounding gate:
 * a finding's quote is checked against the recorded exchanges, not a paraphrase.
 *
 * Determinism guarantees:
 *   - redaction is deterministic (same secret -> same [REDACTED]), so grounding
 *     against the redacted body is still a byte-exact match;
 *   - every exchange is SHA-256 tagged over its canonical form, so a captured
 *     exchange cannot be silently rewritten;
 *   - the store is append-only within the session (plus a clear() for lifecycle).
 */

import { createHash } from "node:crypto";
import { redactSecrets } from "./secrets.js";
import { verifyEvidenceGrounding, type GroundingResult } from "./evidence-grounding.js";

export interface HttpExchangeInput {
  method: string;
  url: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  status: number;
  response_headers?: Record<string, string>;
  response_body?: string;
  note?: string;
}

export interface HttpExchange extends HttpExchangeInput {
  id: string;
  recorded: string;
  sha256: string;
}

export interface TrafficFilter {
  method?: string;
  url?: string;
  status?: number;
  limit?: number;
}

const store: HttpExchange[] = [];
let counter = 0;
const MAX_STORE = 5000;

function redactHeaders(h?: Record<string, string>): Record<string, string> | undefined {
  if (!h) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    // Redact with the header NAME as context so field-name patterns
    // (e.g. `authorization: bearer …`, `set-cookie: …`) match — redacting a
    // bare value in isolation loses the key that tells us it is a secret.
    const prefix = `${k}: `;
    const full = redactSecrets(prefix + v);
    out[k] = full.startsWith(prefix) ? full.slice(prefix.length) : v;
  }
  return out;
}

function canonicalize(x: HttpExchangeInput): string {
  return JSON.stringify({
    method: x.method,
    url: x.url,
    request_headers: x.request_headers ?? {},
    request_body: x.request_body ?? "",
    status: x.status,
    response_headers: x.response_headers ?? {},
    response_body: x.response_body ?? "",
  });
}

/** Record one HTTP request/response exchange (redacted + SHA-256 tagged). */
export function recordExchange(input: HttpExchangeInput): HttpExchange {
  const redacted: HttpExchangeInput = {
    method: input.method,
    url: redactSecrets(input.url),
    request_headers: redactHeaders(input.request_headers),
    request_body: input.request_body !== undefined ? redactSecrets(input.request_body) : undefined,
    status: input.status,
    response_headers: redactHeaders(input.response_headers),
    response_body: input.response_body !== undefined ? redactSecrets(input.response_body) : undefined,
    note: input.note,
  };
  counter += 1;
  const ex: HttpExchange = {
    ...redacted,
    id: `TRAFFIC-${String(counter).padStart(6, "0")}`,
    recorded: new Date().toISOString(),
    sha256: createHash("sha256").update(canonicalize(redacted)).digest("hex"),
  };
  store.push(ex);
  if (store.length > MAX_STORE) store.splice(0, store.length - MAX_STORE);
  return ex;
}

/** List captured exchanges, optionally filtered. Newest first. */
export function listExchanges(filter?: TrafficFilter): HttpExchange[] {
  let out = [...store].reverse();
  if (filter?.method) out = out.filter((e) => e.method.toUpperCase() === filter.method!.toUpperCase());
  if (filter?.url) out = out.filter((e) => e.url.includes(filter.url!));
  if (filter?.status !== undefined) out = out.filter((e) => e.status === filter.status);
  if (filter?.limit) out = out.slice(0, filter.limit);
  return out;
}

/** Get one exchange by id (exact or trailing suffix). */
export function getExchange(id: string): HttpExchange | undefined {
  return store.find((e) => e.id === id || e.id.endsWith(id));
}

/** Clear the session traffic store. Returns the number of cleared exchanges. */
export function clearTraffic(): number {
  const n = store.length;
  store.length = 0;
  return n;
}

/** Traffic session stats. */
export function trafficStats(): { recorded: number; oldest: string | null; newest: string | null } {
  return {
    recorded: store.length,
    oldest: store.length ? store[0].recorded : null,
    newest: store.length ? store[store.length - 1].recorded : null,
  };
}

/** Ground a claimed evidence string against the recorded traffic (the automatic
 *  byte-exact evidence check). Grounds against each matching exchange's response
 *  body (the text the model actually quotes). Pass an exchange id to restrict to
 *  one exchange, or omit to project across all recorded traffic. */
export function groundTrafficEvidence(evidence: string, exchangeId?: string): GroundingResult {
  const exchanges = exchangeId ? store.filter((e) => e.id === exchangeId || e.id.endsWith(exchangeId)) : store;
  if (exchanges.length === 0) {
    return { grounded: false, verdict: "ungrounded", method: null, detail: "no traffic recorded (or no matching exchange id)" };
  }
  const outputs = exchanges.map((e) => e.response_body ?? JSON.stringify({ method: e.method, url: e.url, status: e.status }));
  return verifyEvidenceGrounding(evidence, outputs);
}

// ---------------------------------------------------------------------------
// Automatic recorder — wrap global fetch so every probe/exploit request lands
// in the ledger without the model having to remember to call traffic_record.
// Opt-in, idempotent, reversible, and never allowed to break the real request.
// ---------------------------------------------------------------------------

export interface RecorderOptions {
  /** Return true to SKIP recording this URL (e.g. filter recon noise). */
  skip?: (url: string) => boolean;
  /** Only record these HTTP methods (default: all). */
  methods?: string[];
}

let recorderInstalled = false;
let originalFetch: typeof globalThis.fetch | null = null;

function headersToRecord(h: HeadersInit | Headers | undefined | null): Record<string, string> | undefined {
  if (!h) return undefined;
  const out: Record<string, string> = {};
  try {
    if (typeof Headers !== "undefined" && h instanceof Headers) {
      h.forEach((v, k) => { out[k] = v; });
    } else if (Array.isArray(h)) {
      for (const [k, v] of h) out[k] = v;
    } else {
      for (const [k, v] of Object.entries(h as Record<string, string>)) out[k] = String(v);
    }
  } catch { /* ignore */ }
  return Object.keys(out).length ? out : undefined;
}

function bodyToRecord(body: BodyInit | null | undefined): string | undefined {
  if (body === undefined || body === null) return undefined;
  try {
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return body.toString();
    if (typeof body === "object" && "toString" in (body as object)) return String(body);
  } catch { /* ignore */ }
  return undefined;
}

function urlOf(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (typeof URL !== "undefined" && input instanceof URL) return input.toString();
  return (input as Request)?.url ?? "";
}

/** Install the fetch recorder. Idempotent: a second call is a no-op that
 *  returns `installed: false` with an uninstall handle. */
export function installTrafficRecorder(options?: RecorderOptions): { installed: boolean; uninstall: () => void } {
  if (recorderInstalled) return { installed: false, uninstall: uninstallTrafficRecorder };
  const orig = globalThis.fetch;
  originalFetch = orig;
  const methods = options?.methods?.map((m) => m.toUpperCase());
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const res = await orig(input, init);
    try {
      const url = urlOf(input);
      const method = String((init as RequestInit | undefined)?.method ?? (input as Request)?.method ?? "GET").toUpperCase();
      const skip = !url || (options?.skip?.(url) ?? false) || (methods ? !methods.includes(method) : false);
      if (!skip) {
        let responseBody: string | undefined;
        try { responseBody = await res.clone().text(); } catch { responseBody = undefined; }
        recordExchange({
          method,
          url,
          request_headers: headersToRecord((init as RequestInit | undefined)?.headers),
          request_body: bodyToRecord((init as RequestInit | undefined)?.body),
          status: res.status,
          response_headers: headersToRecord(res.headers),
          response_body: responseBody,
        });
      }
    } catch { /* recording must NEVER break the actual request */ }
    return res;
  };
  recorderInstalled = true;
  return { installed: true, uninstall: uninstallTrafficRecorder };
}

/** Restore the original fetch (no-op if the recorder was never installed). */
export function uninstallTrafficRecorder(): void {
  if (recorderInstalled && originalFetch) {
    globalThis.fetch = originalFetch;
    originalFetch = null;
    recorderInstalled = false;
  }
}

export function isTrafficRecorderInstalled(): boolean {
  return recorderInstalled;
}
