---
name: adversarial-review
description: Use before confirming a verified finding as real. Run the ten adversarial questions, score confidence, dedup shared-root findings, and reject anything that does not survive. This is the anti-hallucination gate between "hypothesis" and "confirmed finding".
---

# Adversarial review (anti-hallucination gate)

"A hypothesis is not a finding. AI reasoning is not evidence. Severity is not
confidence." Before any finding is confirmed, attack it from every angle.

## The ten questions (§15)

For each finding, answer these with evidence — not vibes:

1. Is the vulnerable code actually **reachable**?
2. Is **authentication** required (and did we account for it)?
3. Is **authorization** enforced elsewhere (would the attacker be blocked)?
4. Is there **middleware/WAF/sanitizer** protection?
5. Is the input actually **attacker-controlled**?
6. Is the **sink** reachable from that input?
7. Is the observed behavior just **caching** (ETag/304)?
8. Is the exploit **reproducible** (marker confirmed, not one-off)?
9. Does the **negative control** remain inert?
10. Is the **impact** accurately classified (CWE/CVSS, not inflated)?

## Verdict

- Any **fail** → REJECTED. Drop it, do not soften it.
- Fewer than 3 clear **passes** → NEEDS_MORE_EVIDENCE. Go back to `verify-finding`.
- 3+ passes, 0 fails → CONFIRMED.

## Scoring + dedup

- `confidence_score` — deterministic weighted confidence (evidence, verification,
  reachability). Do not invent a confidence number.
- `dedup_findings` — collapse findings that share a root cause before reporting.
- `finding_transition` — advance only via the strict lifecycle.

## Why

A false positive costs the user their reputation. Rejecting a real bug is
recoverable (it stays in memory); reporting a fake one is not.
