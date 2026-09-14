/** STRIKE validation engine — the verdict layer.
 *
 * Phase 3. Where a scanner hit is a HYPOTHESIS, STRIKE turns it into a VERDICT:
 * a live request with a MARKER, a NEGATIVE CONTROL, and a BASELINE, whose
 * combined result moves a canonical Finding through its lifecycle
 * (hypothesis -> validating -> confirmed / false_positive / unconfirmed).
 *
 * Verdict logic (§13-15 of the development doc):
 *
 *   baseline:  a normal request records the application's default behaviour.
 *   marker:    the candidate payload (a unique marker) is injected.
 *   control:   a benign lookalike is injected in the same position.
 *
 *   marker reflected AND control NOT reflected  -> CONFIRMED
 *   marker reflected AND control also reflected -> FALSE_POSITIVE (indistinguishable
 *                                                   from benign reflection)
 *   marker NOT reflected                        -> UNCONFIRMED (cannot prove)
 *   request failed / blocked                    -> BLOCKED
 *
 * Every response is captured as a redacted, SHA-256-tagged evidence artifact.
 */
import { redactSecrets, sha256, type MakeEvidenceInput } from "./evidence.js";
import { confirmFinding, rejectFinding, transition, type Finding, type FindingStatus } from "./finding.js";
import { scanSinks, detectSourceLeak, type SinkHit } from "./sinks.js";
import { researchHeaders } from "./http.js";

const DEFAULT_TIMEOUT_MS = 15000;

interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}

async function httpRequest(url: string, method: "GET" | "POST", data?: string, headers?: Record<string, string>, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<HttpResponse> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      body: method === "POST" ? data : undefined,
      headers: { "User-Agent": "blitzstrike/1.0", ...researchHeaders(), ...(headers ?? {}) },
      signal: controller.signal,
      redirect: "follow",
    });
    const body = await res.text();
    const hdrs: Record<string, string> = {};
    res.headers.forEach((v, k) => { hdrs[k] = v; });
    return { status: res.status, body: body.slice(0, 20000), headers: hdrs };
  } catch (e) {
    return { status: 0, body: String(e), headers: {} };
  } finally {
    clearTimeout(t);
  }
}

function defaultMarker(): string {
  return `BS${Date.now().toString(36).toUpperCase()}${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

/** Inject a value into a URL (query param) or POST body at a placeholder. */
function inject(target: string, value: string, param: string): string {
  const placeholder = "{{MARKER}}";
  if (target.includes(placeholder)) return target.split(placeholder).join(value);
  if (target.includes("?")) return `${target}&${param}=${encodeURIComponent(value)}`;
  return `${target}?${param}=${encodeURIComponent(value)}`;
}

// ---------------------------------------------------------------------------
// WAF bypass — when the marker is blocked by a WAF, try evasion variants before
// declaring unconfirmed. A WAF returns a block page, not the normal response.
// ---------------------------------------------------------------------------

const WAF_BLOCK_SIGNATURES = [
  /akses dibatasi/i, /access denied/i, /request blocked/i, /attention required/i,
  /not acceptable/i, /mod_?security/i, /big-?ip/i, /security policy/i,
  /your request has been blocked/i, /blocked by the/i, /waf/i, /firewall/i,
  /403 forbidden/i, /406 not acceptable/i, /request rejected/i,
];

export function isWafBlock(status: number, body: string): boolean {
  if (status === 403 || status === 406) return true;
  const head = body.slice(0, 4000);
  return WAF_BLOCK_SIGNATURES.some((re) => re.test(head));
}

/** Transform a payload into WAF-evasion variants (decode-once-more, case, entity, comment, separator). */
export function bypassVariants(marker: string): Array<{ technique: string; value: string }> {
  const v: Array<{ technique: string; value: string }> = [];
  v.push({ technique: "double_url_encode", value: encodeURIComponent(marker) });
  v.push({ technique: "case_variation", value: marker.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join("") });
  v.push({ technique: "html_entity", value: marker.replace(/['"<>]/g, (c) => `&#${c.charCodeAt(0)};`) });
  v.push({ technique: "comment_split", value: marker.replace(/\b(SELECT|UNION|AND|OR|FROM|WHERE|INSERT|UPDATE|DELETE|SLEEP|WAITFOR)\b/gi, "$1/**/") });
  v.push({ technique: "separator", value: marker.replace(/ /g, "%0a") });
  v.push({ technique: "null_byte", value: marker + "%00" });
  return v.filter((x) => x.value && x.value !== marker);
}

export interface StrikeVerifyInput {
  url: string;
  method?: "GET" | "POST";
  /** URL or body template. A literal {{MARKER}} is replaced with marker/control. */
  data?: string;
  headers?: Record<string, string>;
  /** Unique string the payload should reflect. Defaults to a random token. */
  marker?: string;
  /** Benign lookalike injected in the same position (negative control). */
  control?: string;
  /** Query/body parameter name to inject into when no {{MARKER}} placeholder. */
  param?: string;
  /** Per-request timeout in milliseconds (default 15000). */
  timeout?: number;
}

export type VerdictStatus = "confirmed" | "likely" | "unconfirmed" | "false_positive" | "blocked";

export interface StrikeVerdict {
  status: VerdictStatus;
  marker_reflected: boolean;
  control_reflected: boolean;
  /** WAF-bypass technique that succeeded (if the marker was WAF-blocked then bypassed). */
  bypass?: string;
  baseline: { status: number; body_preview: string; body_hash: string };
  marker_response: { status: number; body_preview: string; body_hash: string };
  control_response: { status: number; body_preview: string; body_hash: string };
  reason: string;
  evidence: MakeEvidenceInput[];
  leaked_sinks?: SinkHit[];
}

/** Run baseline + marker + control, and produce a deterministic verdict. */
export async function strikeVerify(input: StrikeVerifyInput): Promise<StrikeVerdict> {
  const method = input.method ?? "GET";
  const param = input.param ?? "q";
  const marker = input.marker ?? defaultMarker();
  const control = input.control ?? defaultMarker(); // distinct benign lookalike
  const baseUrl = input.url;
  const timeoutMs = input.timeout ?? DEFAULT_TIMEOUT_MS;

  const baselineTarget = inject(baseUrl, "", param).replace(/[?&]q=$/, "").replace(/[?&]$/, "");
  const markerTarget = inject(baseUrl, marker, param);
  const controlTarget = inject(baseUrl, control, param);

  const baseline = await httpRequest(baselineTarget, method, input.data, input.headers, timeoutMs);
  const markerResp = await httpRequest(markerTarget, method, input.data, input.headers, timeoutMs);
  const controlResp = await httpRequest(controlTarget, method, input.data, input.headers, timeoutMs);

  if (baseline.status === 0 || markerResp.status === 0) {
    return {
      status: "blocked",
      marker_reflected: false,
      control_reflected: false,
      baseline: { status: baseline.status, body_preview: redactSecrets(baseline.body.slice(0, 400)), body_hash: sha256(baseline.body) },
      marker_response: { status: markerResp.status, body_preview: redactSecrets(markerResp.body.slice(0, 400)), body_hash: sha256(markerResp.body) },
      control_response: { status: controlResp.status, body_preview: redactSecrets(controlResp.body.slice(0, 400)), body_hash: sha256(controlResp.body) },
      reason: "request failed or target unreachable — cannot validate",
      evidence: [],
    };
  }

  let markerReflected = markerResp.body.includes(marker);
  let controlReflected = controlResp.body.includes(control);

  // WAF bypass — when the marker is blocked by a WAF (block page / 403/406),
  // try evasion variants (double-encode, case, entity, comment, separator, null
  // byte) before declaring unconfirmed. A variant that reflects the ORIGINAL
  // marker means the WAF was bypassed and the sink is real.
  let bypass: string | undefined;
  if (!markerReflected && isWafBlock(markerResp.status, markerResp.body)) {
    for (const v of bypassVariants(marker)) {
      const byTarget = inject(baseUrl, v.value, param);
      const byResp = await httpRequest(byTarget, method, input.data, input.headers, timeoutMs);
      if (byResp.body.includes(marker)) {
        markerReflected = true;
        bypass = v.technique;
        break;
      }
    }
  }

  let status: VerdictStatus;
  let reason: string;
  if (markerReflected && !controlReflected) {
    status = "confirmed";
    reason = bypass
      ? `marker reflected after WAF bypass (${bypass}); negative control did not — the sink reflects attacker-controlled input (real finding)`
      : "marker reflected; negative control did not — the sink reflects attacker-controlled input (real finding)";
  } else if (markerReflected && controlReflected) {
    status = "false_positive";
    reason = "marker AND negative control both reflected — behaviour is indistinguishable from benign reflection (likely false positive)";
  } else if (!markerReflected && !controlReflected) {
    status = "unconfirmed";
    reason = bypass
      ? `marker not reflected even after WAF bypass attempts (${bypassVariants(marker).length} variants) — reachability/exploitability could not be demonstrated`
      : "marker not reflected — reachability/exploitability could not be demonstrated live";
  } else {
    // control reflected but marker not: anomalous — treat as unconfirmed.
    status = "unconfirmed";
    reason = "negative control reflected but marker did not — inconsistent, requires deeper analysis";
  }

  const evidence: MakeEvidenceInput[] = [
    {
      type: "baseline_comparison",
      description: `Baseline response (status ${baseline.status}) for ${redactSecrets(baselineTarget)}`,
      artifacts: [{ name: "baseline", kind: "http_response", content: `${baseline.status}\n${baseline.body}` }],
    },
    {
      type: "validation_result",
      description: `Marker '${redactSecrets(marker)}' reflected=${markerReflected}; control reflected=${controlReflected}`,
      artifacts: [{ name: "marker_response", kind: "http_response", content: `${markerResp.status}\n${markerResp.body}` }],
    },
    {
      type: "negative_control",
      description: `Negative control '${redactSecrets(control)}' reflected=${controlReflected}`,
      artifacts: [{ name: "control_response", kind: "http_response", content: `${controlResp.status}\n${controlResp.body}` }],
    },
  ];

  // Scan every captured response for leaked sinks (a traceback in the marker/
  // baseline/control response may reveal eval()/SECRET_KEY/etc. beyond the
  // finding being verified). Dedupe across the three responses.
  const leakedSinks: SinkHit[] = [];
  const seen = new Set<string>();
  for (const resp of [baseline, markerResp, controlResp]) {
    if (!detectSourceLeak(resp.body)) continue;
    for (const s of scanSinks(resp.body)) {
      const k = `${s.type}:${s.label}:${s.line}`;
      if (seen.has(k)) continue;
      seen.add(k);
      leakedSinks.push(s);
    }
  }

  return {
    status,
    marker_reflected: markerReflected,
    control_reflected: controlReflected,
    bypass,
    baseline: { status: baseline.status, body_preview: redactSecrets(baseline.body.slice(0, 400)), body_hash: sha256(baseline.body) },
    marker_response: { status: markerResp.status, body_preview: redactSecrets(markerResp.body.slice(0, 400)), body_hash: sha256(markerResp.body) },
    control_response: { status: controlResp.status, body_preview: redactSecrets(controlResp.body.slice(0, 400)), body_hash: sha256(controlResp.body) },
    leaked_sinks: leakedSinks.length ? leakedSinks : undefined,
    reason,
    evidence,
  };
}

export interface FileReadVerifyInput {
  url: string;
  method?: "GET" | "POST";
  /** Inject the path as a named query parameter (default "path"). */
  param?: string;
  /** Treat the raw request body as the filesystem path (POST body = path). */
  bodyRaw?: boolean;
  headers?: Record<string, string>;
  /** Marker file to read (default /etc/passwd). */
  markerPath?: string;
  timeoutMs?: number;
}

export interface FileReadVerdict {
  status: "confirmed" | "unconfirmed" | "blocked";
  file_read: boolean;
  marker_file_content: boolean;
  control_file_content: boolean;
  marker_status: number;
  control_status: number;
  marker_preview: string;
  control_preview: string;
  reason: string;
}

function buildFileReadRequest(url: string, path: string, param?: string, bodyRaw?: boolean): { url: string; data?: string } {
  if (bodyRaw) return { url, data: path };
  return { url: inject(url, path, param ?? "path") };
}

/** Verify an arbitrary-file-read / path-traversal hypothesis DETERMINISTICALLY:
 * read a marker file (/etc/passwd) and a non-existent negative-control path,
 * then compare. A file read is CONFIRMED only when the marker returns file
 * content and the control does not — never from reasoning alone. When both
 * requests return an identical gate (e.g. a 500 auth wall), the verdict is
 * unconfirmed with an explicit reason instead of leaving a bare hypothesis. */
export async function verifyFileRead(input: FileReadVerifyInput): Promise<FileReadVerdict> {
  const method = input.method ?? "POST";
  const markerPath = input.markerPath ?? "/etc/passwd";
  const controlPath = `/bs-nonexistent-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const markerReq = buildFileReadRequest(input.url, markerPath, input.param, input.bodyRaw);
  const controlReq = buildFileReadRequest(input.url, controlPath, input.param, input.bodyRaw);

  const markerResp = await httpRequest(markerReq.url, method, markerReq.data, input.headers, timeoutMs);
  const controlResp = await httpRequest(controlReq.url, method, controlReq.data, input.headers, timeoutMs);

  // Canonical /etc/passwd signature: the leading "root:x:0:0:" line.
  const passwdRe = /(^|\n)root:[x*!][^:]*:0:0:/m;
  const markerFile = passwdRe.test(markerResp.body);
  const controlFile = passwdRe.test(controlResp.body);

  let status: FileReadVerdict["status"];
  let reason: string;
  if (markerResp.status === 0 && controlResp.status === 0) {
    status = "blocked";
    reason = "both marker and control requests failed — target unreachable";
  } else if (markerFile && !controlFile) {
    status = "confirmed";
    reason = "marker file (/etc/passwd) content returned while the non-existent negative control did not — arbitrary file read confirmed";
  } else if (markerFile && controlFile) {
    status = "unconfirmed";
    reason = "marker and negative control both returned passwd-like content — indistinguishable from a fixed response";
  } else if (markerResp.status === controlResp.status && markerResp.body === controlResp.body) {
    status = "unconfirmed";
    reason = `marker and control returned identical responses (HTTP ${markerResp.status}) — likely an auth/session gate; file read not reachable without credentials`;
  } else {
    status = "unconfirmed";
    reason = "marker file content not returned — arbitrary file read could not be demonstrated live";
  }

  return {
    status,
    file_read: markerFile && !controlFile,
    marker_file_content: markerFile,
    control_file_content: controlFile,
    marker_status: markerResp.status,
    control_status: controlResp.status,
    marker_preview: redactSecrets(markerResp.body.slice(0, 300)),
    control_preview: redactSecrets(controlResp.body.slice(0, 300)),
    reason,
  };
}

/** Resolve a canonical finding from a STRIKE verdict, advancing its lifecycle. */
export function resolveFinding(finding: Finding, verdict: StrikeVerdict): Finding {
  let f: Finding = finding;
  if (f.status === "hypothesis") {
    f = transition(f, "validating");
  }
  switch (verdict.status) {
    case "confirmed":
      return confirmFinding(f, {
        evidence: verdict.evidence,
        negative_control: true,
        baseline: true,
      });
    case "false_positive":
      return rejectFinding(f, "false_positive", verdict.reason, verdict.evidence);
    case "blocked":
      return rejectFinding(f, "blocked", verdict.reason, verdict.evidence);
    case "unconfirmed":
    case "likely":
    default: {
      // Not enough to confirm; keep the hypothesis alive with validation metadata.
      return {
        ...f,
        validation: { performed: true, status: verdict.status === "likely" ? "likely" : "unconfirmed", negative_control: verdict.control_reflected === false, baseline: true },
        remediation: { ...f.remediation, note: verdict.reason },
        timestamps: { ...f.timestamps, updated: new Date().toISOString() },
      };
    }
  }
}

export type { Finding, FindingStatus };
