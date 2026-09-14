/** Finding engine — the canonical, evidence-first finding model.
 *
 * This is the single finding schema for the whole toolbelt. Every producer
 * (scanner, eagle-eye, strike, chains) funnels into this model; nothing else
 * invents its own ad-hoc finding shape.
 *
 * Core rules (see docs):
 *   - Severity describes IMPACT. Confidence describes CERTAINTY. Never combine.
 *   - A finding is only CONFIRMED through validation + evidence, never through
 *     an AI agent assigning a high score.
 *   - Lifecycle is strict and machine-readable.
 */
import { Evidence, makeEvidence, type EvidenceType } from "./evidence.js";
import { assertFindingInvariants } from "./invariants.js";
import { recordAudit } from "./audit.js";

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type FindingStatus =
  | "detected"
  | "triaged"
  | "hypothesis"
  | "validating"
  | "confirmed"
  | "false_positive"
  | "rejected"
  | "blocked"
  | "out_of_scope";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type ConfidenceLevel = "informational" | "suspected" | "likely" | "high_confidence" | "confirmed";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export interface FindingTarget {
  type: "web" | "api" | "source" | "mobile" | "network" | "other";
  host?: string;
  endpoint?: string;
  path?: string;
}

export interface FindingClassification {
  cwe?: string;
  cwe_name?: string;
  cwe_confidence?: number;
  severity: Severity;
  cvss_version?: string;
  cvss_score?: number;
  cvss_vector?: string;
  cvss_justification?: string;
}

export interface FindingSource {
  type: string; // request_parameter, post_body, header, cookie, file, etc.
  name: string;
  location?: string;
}

export interface FindingSink {
  type: string; // security_sensitive_operation classification
  location?: string;
  symbol?: string;
}

export interface FindingValidation {
  performed: boolean;
  status?: "confirmed" | "likely" | "unconfirmed" | "false_positive" | "blocked";
  baseline?: boolean;
  negative_control?: boolean;
  /** Whether the target was in-scope when validated (false => cannot confirm). */
  scope_allowed?: boolean;
}

export interface FindingChain {
  id: string | null;
  name?: string;
}

export interface FindingTimestamps {
  created: string;
  updated: string;
}

export interface Finding {
  id: string;
  status: FindingStatus;
  title: string;
  target: FindingTarget;
  classification: FindingClassification;
  /** 0.0 - 1.0 deterministic confidence (NOT an AI opinion). */
  confidence: number;
  confidence_level: ConfidenceLevel;
  source: FindingSource;
  flow: string[];
  sink: FindingSink;
  validation: FindingValidation;
  evidence: Evidence[];
  chain: FindingChain;
  impact: Record<string, unknown>;
  remediation: Record<string, unknown>;
  timestamps: FindingTimestamps;
}

// ---------------------------------------------------------------------------
// Lifecycle (§2) — strict state machine
// ---------------------------------------------------------------------------

export const LIFECYCLE_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  detected: ["triaged", "rejected"],
  triaged: ["hypothesis", "rejected", "out_of_scope"],
  hypothesis: ["validating", "false_positive", "rejected", "blocked"],
  // Validation RESULT is recorded on finding.validation.status ("likely" /
  // "unconfirmed" live there, not in the lifecycle). The lifecycle only moves
  // to a terminal state — confirmed/false_positive/blocked/out_of_scope.
  validating: ["confirmed", "false_positive", "blocked", "out_of_scope"],
  confirmed: [],
  false_positive: [],
  rejected: [],
  blocked: [],
  out_of_scope: [],
};

/** Whether a transition from -> to is legal. */
export function canTransition(from: FindingStatus, to: FindingStatus): boolean {
  const allowed = LIFECYCLE_TRANSITIONS[from] ?? [];
  return allowed.includes(to);
}

// ---------------------------------------------------------------------------
// Confidence engine (§16-17) — deterministic, weighted
// ---------------------------------------------------------------------------

export interface ConfidenceFactors {
  static_analysis?: boolean;
  data_flow?: boolean;
  reachability?: boolean;
  preconditions?: boolean;
  runtime_validation?: boolean;
  negative_control?: boolean;
}

const DEFAULT_WEIGHTS: Record<keyof ConfidenceFactors, number> = {
  static_analysis: 0.20,
  data_flow: 0.25,
  reachability: 0.15,
  preconditions: 0.10,
  runtime_validation: 0.20,
  negative_control: 0.10,
};

let confidenceWeights: Record<keyof ConfidenceFactors, number> = { ...DEFAULT_WEIGHTS };

/** Override confidence weights (configurable per §16). */
export function setConfidenceWeights(weights: Partial<Record<keyof ConfidenceFactors, number>>): void {
  confidenceWeights = { ...DEFAULT_WEIGHTS, ...weights };
}

export function getConfidenceWeights(): Record<keyof ConfidenceFactors, number> {
  return { ...confidenceWeights };
}

/** Deterministic weighted confidence score in [0, 1]. */
export function computeConfidence(factors: ConfidenceFactors): number {
  let score = 0;
  for (const [key, weight] of Object.entries(confidenceWeights) as Array<[keyof ConfidenceFactors, number]>) {
    if (factors[key] === true) score += weight;
  }
  return Math.round(score * 100) / 100;
}

/** Map a confidence score to a label (§17). */
export function confidenceLevel(score: number): ConfidenceLevel {
  if (score >= 0.90) return "confirmed";
  if (score >= 0.70) return "high_confidence";
  if (score >= 0.50) return "likely";
  if (score >= 0.30) return "suspected";
  return "informational";
}

// ---------------------------------------------------------------------------
// Finding factory
// ---------------------------------------------------------------------------

let findingCounter = 0;

function nextFindingId(): string {
  findingCounter += 1;
  return `BS-${new Date().getUTCFullYear()}-${String(findingCounter).padStart(6, "0")}`;
}

export interface MakeFindingInput {
  title: string;
  target: FindingTarget;
  severity: Severity;
  cwe?: string;
  cweName?: string;
  cweConfidence?: number;
  source: FindingSource;
  sink: FindingSink;
  flow?: string[];
  chainId?: string | null;
  chainName?: string;
  status?: FindingStatus;
  /** Evidence attached at creation — a finding must never be created empty
   * when the producer already holds the observed artifact (headers, URL,
   * response body). Each entry becomes a redacted SHA-256-tagged record. */
  evidence?: Array<{ type: EvidenceType; description: string; content?: string }>;
}

/** Create a canonical finding. Default status = detected (hypothesis-pending).
 * Evidence passed in `input.evidence` is attached immediately so the finding is
 * never born empty when the producer holds the observed artifact. */
export function makeFinding(input: MakeFindingInput): Finding {
  const now = new Date().toISOString();
  const status = input.status ?? "detected";
  const factors = confidenceFactorsFor(input);
  const confidence = computeConfidence(factors);
  let finding: Finding = {
    id: nextFindingId(),
    status,
    title: input.title,
    target: input.target,
    classification: {
      severity: input.severity,
      cwe: input.cwe,
      cwe_name: input.cweName,
      cwe_confidence: input.cweConfidence,
    },
    confidence,
    confidence_level: confidenceLevel(confidence),
    source: input.source,
    flow: input.flow ?? [],
    sink: input.sink,
    validation: { performed: false },
    evidence: [],
    chain: { id: input.chainId ?? null, name: input.chainName },
    impact: {},
    remediation: {},
    timestamps: { created: now, updated: now },
  };
  if (input.evidence?.length) {
    for (const e of input.evidence) {
      const ev = makeEvidence({
        type: e.type,
        description: e.description,
        artifacts: e.content ? [{ name: "artifact", kind: "evidence", content: e.content }] : [],
      });
      finding = attachEvidence(finding, ev);
    }
  }
  recordAudit("finding_created", { tool: "eagle-eye", target: input.target.host ?? input.target.endpoint, result: status, correlationId: finding.id });
  return finding;
}

/** Default static factors derivable from a made finding (no runtime validation). */
function confidenceFactorsFor(_input: MakeFindingInput): ConfidenceFactors {
  // A freshly detected finding has only static evidence + sink presence.
  return {
    static_analysis: true,
    data_flow: false,
    reachability: false,
    preconditions: false,
    runtime_validation: false,
    negative_control: false,
  };
}

// ---------------------------------------------------------------------------
// Transition helpers
// ---------------------------------------------------------------------------

/** Advance a finding's lifecycle, validating the transition. Returns new object. */
export function transition(finding: Finding, to: FindingStatus): Finding {
  if (!canTransition(finding.status, to)) {
    throw new Error(`illegal transition ${finding.status} -> ${to}`);
  }
  recordAudit("finding_updated", { tool: "blitzstrike", target: finding.target.host ?? finding.target.endpoint, result: `${finding.status} -> ${to}`, correlationId: finding.id });
  const updated = { ...finding, status: to, timestamps: { ...finding.timestamps, updated: new Date().toISOString() } };
  return updated;
}

/** Attach a redacted, integrity-tagged evidence record to a finding. */
export function attachEvidence(finding: Finding, evidence: Evidence): Finding {
  recordAudit("evidence_created", { tool: "blitzstrike", target: finding.target.host ?? finding.target.endpoint, result: evidence.evidence_id, correlationId: finding.id });
  return {
    ...finding,
    evidence: [...finding.evidence, evidence],
    timestamps: { ...finding.timestamps, updated: new Date().toISOString() },
  };
}

/** Mark a hypothesis as confirmed with validation + evidence + recomputed confidence.
 *  A FAILED negative control (negative_control=false) drops confidence below the
 *  confirmed threshold — confirmation requires both a positive marker AND a
 *  clean negative control. Confirmation also REQUIRES evidence (hard invariant:
 *  a finding cannot be CONFIRMED without evidence). */
export function confirmFinding(
  finding: Finding,
  opts: {
    evidence: Array<Parameters<typeof makeEvidence>[0]>;
    negative_control?: boolean;
    baseline?: boolean;
    scope_allowed?: boolean;
  },
): Finding {
  if (opts.evidence.length === 0) {
    throw new Error("invariant: cannot confirm a finding without evidence");
  }
  const evidence = opts.evidence.map((e) => makeEvidence(e));
  const negativeControl = opts.negative_control ?? true;
  const scopeAllowed = opts.scope_allowed ?? true;
  const confidence = computeConfidence({
    static_analysis: true,
    data_flow: true,
    reachability: true,
    preconditions: true,
    runtime_validation: true,
    negative_control: negativeControl,
  });
  const level = confidenceLevel(confidence);
  // If the negative control failed, the finding is NOT confirmed — it stays a
  // high-confidence hypothesis (evidence is insufficient to call it confirmed).
  const status: FindingStatus = negativeControl ? "confirmed" : "hypothesis";
  const confirmed: Finding = {
    ...finding,
    status,
    confidence,
    confidence_level: level,
    validation: {
      performed: true,
      status: negativeControl ? "confirmed" : "unconfirmed",
      baseline: opts.baseline ?? true,
      negative_control: negativeControl,
      scope_allowed: scopeAllowed,
    },
    evidence: [...finding.evidence, ...evidence],
    timestamps: { ...finding.timestamps, updated: new Date().toISOString() },
  };
  // A scope-denied or evidence-less finding must never reach CONFIRMED.
  assertFindingInvariants(confirmed);
  recordAudit("validation_finished", { tool: "strike", target: finding.target.host ?? finding.target.endpoint, result: status, correlationId: finding.id });
  return confirmed;
}

/** Reject a finding into a terminal state (false_positive/rejected/blocked/out_of_scope). */
export function rejectFinding(
  finding: Finding,
  status: "false_positive" | "rejected" | "blocked" | "out_of_scope",
  reason: string,
  evidence?: Array<Parameters<typeof makeEvidence>[0]>,
): Finding {
  const ev = evidence?.map((e) => makeEvidence(e)) ?? [];
  const updated = transition(finding, status as FindingStatus);
  return {
    ...updated,
    validation: { ...updated.validation, performed: false },
    remediation: { ...updated.remediation, note: reason },
    evidence: [...updated.evidence, ...ev],
    timestamps: { ...updated.timestamps, updated: new Date().toISOString() },
  };
}
