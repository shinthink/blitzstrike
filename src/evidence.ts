/** Evidence engine — the verdict layer of Blitz Strike.
 *
 * A scan hit is a hypothesis; evidence is the verdict. Every CONFIRMED finding
 * must carry structured, integrity-tagged, secret-redacted evidence. Evidence
 * is append-only whenever practical — once a finding is confirmed, its evidence
 * must not be silently rewritten.
 */
import { createHash } from "node:crypto";
import { VERSION } from "./version.js";
import { redactSecrets } from "./secrets.js";

export { redactSecrets, REDACTION_PATTERNS } from "./secrets.js";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export type EvidenceType =
  | "source_location"
  | "source_symbol"
  | "data_flow"
  | "sink_location"
  | "request"
  | "response"
  | "baseline_comparison"
  | "validation_result"
  | "negative_control"
  | "application_state"
  | "tool_output"
  | "chain_execution";

export interface EvidenceArtifact {
  name: string;
  kind: string;
  /** Redacted content — never store raw secrets. */
  content: string;
  sha256: string;
}

/** Chain-of-custody provenance (§16): who produced this evidence, from what. */
export interface EvidenceProvenance {
  tool: string;
  version: string;
  target?: string;
  scope?: string;
  parentEvidence?: string[];
}

export interface Evidence {
  evidence_id: string;
  type: EvidenceType;
  description: string;
  source?: Record<string, unknown>;
  sink?: Record<string, unknown>;
  artifacts: EvidenceArtifact[];
  /** ISO timestamp when this evidence was recorded. */
  recorded: string;
  provenance: EvidenceProvenance;
}

// ---------------------------------------------------------------------------
// Secret redaction (§6) — patterns + logic live in secrets.ts (single source).
// ---------------------------------------------------------------------------

/** Whether the text contains a recognizable RAW secret (used by the invariant layer).
 *  Implemented as "does redaction change it" — deterministic and does NOT flag
 *  already-redacted content (e.g. `password=[REDACTED]` is a no-op). */
export function hasSecrets(text: string): boolean {
  return redactSecrets(text) !== text;
}

/** Recursively redact secrets across a string-keyed object/array. */
export function redactObject<T>(value: T): T {
  if (typeof value === "string") return redactSecrets(value) as unknown as T;
  if (Array.isArray(value)) return value.map((v) => redactObject(v)) as unknown as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactObject(v);
    }
    return out as unknown as T;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Integrity (§5) — SHA-256 tagging
// ---------------------------------------------------------------------------

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

// ---------------------------------------------------------------------------
// Evidence factory
// ---------------------------------------------------------------------------

let evidenceCounter = 0;

function nextEvidenceId(): string {
  evidenceCounter += 1;
  return `EV-${String(evidenceCounter).padStart(6, "0")}`;
}

export interface MakeEvidenceInput {
  type: EvidenceType;
  description: string;
  source?: Record<string, unknown>;
  sink?: Record<string, unknown>;
  artifacts?: Array<{ name: string; kind: string; content: string }>;
  provenance?: Partial<EvidenceProvenance>;
}

/** Create a redacted, integrity-tagged evidence record. */
export function makeEvidence(input: MakeEvidenceInput): Evidence {
  const artifacts: EvidenceArtifact[] = (input.artifacts ?? []).map((a) => {
    const content = redactSecrets(a.content);
    return { name: a.name, kind: a.kind, content, sha256: sha256(content) };
  });

  return {
    evidence_id: nextEvidenceId(),
    type: input.type,
    description: redactSecrets(input.description),
    source: input.source ? redactObject(input.source) : undefined,
    sink: input.sink ? redactObject(input.sink) : undefined,
    artifacts,
    recorded: new Date().toISOString(),
    provenance: {
      tool: input.provenance?.tool ?? "blitzstrike",
      version: input.provenance?.version ?? VERSION,
      ...(input.provenance?.target ? { target: input.provenance.target } : {}),
      ...(input.provenance?.scope ? { scope: input.provenance.scope } : {}),
      ...(input.provenance?.parentEvidence ? { parentEvidence: input.provenance.parentEvidence } : {}),
    },
  };
}

/** Verify that a stored artifact's content matches its sha256 (integrity check). */
export function verifyArtifact(artifact: EvidenceArtifact): boolean {
  return sha256(artifact.content) === artifact.sha256;
}

/** Verify every artifact in an evidence record. */
export function verifyEvidence(evidence: Evidence): { ok: boolean; failed: string[] } {
  const failed: string[] = [];
  for (const a of evidence.artifacts) {
    if (!verifyArtifact(a)) failed.push(a.name);
  }
  return { ok: failed.length === 0, failed };
}
