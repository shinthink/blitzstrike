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
      headers: { "User-Agent": "blitzstrike/1.0", ...(headers ?? {}) },
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
  baseline: { status: number; body_preview: string; body_hash: string };
  marker_response: { status: number; body_preview: string; body_hash: string };
  control_response: { status: number; body_preview: string; body_hash: string };
  reason: string;
  evidence: MakeEvidenceInput[];
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

  const markerReflected = markerResp.body.includes(marker);
  const controlReflected = controlResp.body.includes(control);

  let status: VerdictStatus;
  let reason: string;
  if (markerReflected && !controlReflected) {
    status = "confirmed";
    reason = "marker reflected; negative control did not — the sink reflects attacker-controlled input (real finding)";
  } else if (markerReflected && controlReflected) {
    status = "false_positive";
    reason = "marker AND negative control both reflected — behaviour is indistinguishable from benign reflection (likely false positive)";
  } else if (!markerReflected && !controlReflected) {
    status = "unconfirmed";
    reason = "marker not reflected — reachability/exploitability could not be demonstrated live";
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

  return {
    status,
    marker_reflected: markerReflected,
    control_reflected: controlReflected,
    baseline: { status: baseline.status, body_preview: redactSecrets(baseline.body.slice(0, 400)), body_hash: sha256(baseline.body) },
    marker_response: { status: markerResp.status, body_preview: redactSecrets(markerResp.body.slice(0, 400)), body_hash: sha256(markerResp.body) },
    control_response: { status: controlResp.status, body_preview: redactSecrets(controlResp.body.slice(0, 400)), body_hash: sha256(controlResp.body) },
    reason,
    evidence,
  };
}

/** Resolve a canonical finding from a STRIKE verdict, advancing its lifecycle. */
export function resolveFinding(finding: Finding, verdict: StrikeVerdict): Finding {
  // hypothesis -> validating (a validation was performed)
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
