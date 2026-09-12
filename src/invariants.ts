/** Finding invariants (§53) — hard, machine-checkable rules.
 *
 * These are the "cannot" rules that make Blitz Strike's findings defensible.
 * They are enforced (thrown) at the transition points and independently
 * re-checkable so tests can assert them as hard invariants — more valuable
 * than simply increasing the test count.
 */
import { verifyEvidence, hasSecrets } from "./evidence.js";
import type { Finding } from "./finding.js";

export interface InvariantViolation {
  invariant: string;
  detail: string;
}

/**
 * Check a finding against every hard invariant. Returns the list of
 * violations (empty = invariant-clean).
 */
export function checkFindingInvariants(finding: Finding): InvariantViolation[] {
  const violations: InvariantViolation[] = [];

  // 1. A finding cannot be CONFIRMED without evidence.
  if (finding.status === "confirmed" && finding.evidence.length === 0) {
    violations.push({ invariant: "confirmed-requires-evidence", detail: `finding ${finding.id} is confirmed with no evidence` });
  }

  // 2. A finding cannot be CONFIRMED if the negative control failed.
  if (finding.status === "confirmed" && finding.validation.negative_control === false) {
    violations.push({ invariant: "confirmed-requires-clean-negative-control", detail: `finding ${finding.id} confirmed with a failed negative control` });
  }

  // 3. A finding cannot be CONFIRMED if scope was denied.
  if (finding.status === "confirmed" && finding.validation.scope_allowed === false) {
    violations.push({ invariant: "confirmed-requires-scope-allowed", detail: `finding ${finding.id} confirmed out of scope` });
  }

  // 4. A secret cannot appear in persisted evidence.
  for (const e of finding.evidence) {
    for (const a of e.artifacts) {
      if (hasSecrets(a.content)) {
        violations.push({ invariant: "no-secret-in-evidence", detail: `evidence ${e.evidence_id} artifact ${a.name} contains a raw secret` });
      }
    }
  }

  // 5. Evidence hash must remain stable (no silent tampering).
  for (const e of finding.evidence) {
    const v = verifyEvidence(e);
    if (!v.ok) {
      violations.push({ invariant: "evidence-hash-stable", detail: `evidence ${e.evidence_id} artifacts ${v.failed.join(",")} failed integrity check` });
    }
  }

  return violations;
}

/** Throw if any hard invariant is violated. */
export function assertFindingInvariants(finding: Finding): void {
  const violations = checkFindingInvariants(finding);
  if (violations.length > 0) {
    throw new Error(`invariant violation: ${violations.map((v) => v.invariant).join(", ")}`);
  }
}

/** Whether a finding is invariant-clean (no violations). */
export function isInvariantClean(finding: Finding): boolean {
  return checkFindingInvariants(finding).length === 0;
}
