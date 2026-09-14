/** Empirical grounding + submission gate.
 *
 *  Two complementary layers that close the gap between "a detector fires" and
 *  "this finding is grounded + submittable":
 *
 *   1. PATTERN LIBRARY — every detector type is traced to its real-world bug
 *      class (CWE), its real-world signature, the escalation chains it composes
 *      into (cross-ref chains.json), and a citable reference. Detection is
 *      derived from this data, never hardcoded.
 *
 *   2. SUBMISSION GATE — a deterministic 7-question checklist (Blitz Strike's
 *      own, evidence-first) that a finding must pass before it is reported.
 *      One failed question = the finding does not ship.
 */
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalId } from "./synonyms.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface Pattern {
  id: string;
  name: string;
  cwe: string;
  real_world: string;
  detection_signatures: string[];
  chain_templates: string[];
  references: string[];
  bypass_techniques?: string[];
  crown_jewels?: string[];
  validation?: string[];
  /** Detector-reported severity (high/medium/critical). */
  severity?: string;
  /** Typical bug-bounty payout range (USD). Lo/hi numeric for expected-value math; `typical_payout` is the display form. */
  payout_min?: number;
  payout_max?: number;
  typical_payout?: string;
}

interface PatternsDoc {
  patterns: Pattern[];
}

let _doc: PatternsDoc | null = null;

function load(): PatternsDoc {
  if (_doc) return _doc;
  try {
    _doc = JSON.parse(readFileSync(join(__dirname, "..", "intelligence", "patterns.json"), "utf8")) as PatternsDoc;
  } catch {
    _doc = { patterns: [] };
  }
  return _doc;
}

/** The empirical grounding record for a detector type / vuln class. */
export function patternLookup(id: string): Pattern | null {
  const canonical = canonicalId(id);
  const p = load().patterns.find((x) => x.id === canonical);
  return p ?? null;
}

/** All pattern records (the full empirical grounding index). */
export function listPatterns(): Pattern[] {
  return load().patterns;
}

/** The escalation chains a detector type composes into (cross-ref chains.json). */
export function chainTemplatesFor(id: string): string[] {
  return patternLookup(id)?.chain_templates ?? [];
}

// ---------------------------------------------------------------------------
// Submission gate — the 7 questions a finding must pass before it ships.
// ---------------------------------------------------------------------------

export interface GateQuestion {
  q: string;
  pass: boolean;
  reason: string;
}

export interface SubmissionGateResult {
  verdict: "pass" | "fail";
  passed: number;
  total: number;
  questions: GateQuestion[];
  /** The first question that failed, if any — the reason to kill the finding. */
  blocker?: string;
}

export interface GateInput {
  type?: string;
  severity?: string;
  /** Is there a copy-paste-ready HTTP request / reproduction step list? */
  reproducible?: boolean;
  /** Is the vulnerable asset in the engagement scope? */
  in_scope?: boolean;
  /** Does it map to an accepted-impact class (not merely informational)? */
  real_impact?: boolean;
  /** Does it work without unrealistic attacker prerequisites? */
  no_privileged_assumption?: boolean;
  /** Was it verified live (marker + negative control), not just a static hint? */
  verified_live?: boolean;
  /** Is evidence attached AND redacted (secrets/PII stripped)? */
  evidence_redacted?: boolean;
  /** Is severity derived (CVSS/confidence), not guessed? */
  severity_derived?: boolean;
}

/** The 7-question gate. Fail-closed: a question passes only when EXPLICITLY
 *  asserted true — a missing/unset field fails (an empty finding is a hypothesis,
 *  not a result). One false = fail (kill the finding). */
export function submissionGate(input: GateInput): SubmissionGateResult {
  const questions: GateQuestion[] = [
    {
      q: "Reproducible — a copy-paste-ready request or step list triggers it?",
      pass: input.reproducible === true,
      reason: "Without an exact reproduction the finding is a hypothesis, not a result.",
    },
    {
      q: "In scope — the vulnerable asset is in the engagement scope?",
      pass: input.in_scope === true,
      reason: "Out-of-scope assets must not be submitted.",
    },
    {
      q: "Real impact — maps to an accepted-impact class, not informational?",
      pass: input.real_impact === true,
      reason: "Informational-only findings dilute the validity ratio.",
    },
    {
      q: "No privileged assumption — works without unrealistic attacker prerequisites?",
      pass: input.no_privileged_assumption === true,
      reason: "'Admin can do X' is a centralization risk, not a vulnerability.",
    },
    {
      q: "Verified live — confirmed with a marker + negative control, not just a static hint?",
      pass: input.verified_live === true,
      reason: "A static hit is a hypothesis until verified live (strike_verify / browser_validate).",
    },
    {
      q: "Evidence attached AND redacted — secrets/PII stripped, integrity-tagged?",
      pass: input.evidence_redacted === true,
      reason: "Evidence must carry SHA-256-tagged, redacted records — no leaked secrets or victim PII.",
    },
    {
      q: "Severity derived — CVSS/confidence computed, not guessed?",
      pass: input.severity_derived === true,
      reason: "Severity is not confidence; derive it, don't assert it.",
    },
  ];

  const failed = questions.find((q) => !q.pass);
  return {
    verdict: failed ? "fail" : "pass",
    passed: questions.filter((q) => q.pass).length,
    total: questions.length,
    questions,
    ...(failed ? { blocker: failed.q } : {}),
  };
}
