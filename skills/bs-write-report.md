---
name: write-report
description: Use when finalizing confirmed findings into a submission-ready report (bug bounty, pentest deliverable, or audit). Produce a report with root cause, reproduction, CVSS, impact, and remediation — indistinguishable from a top-tier human hunter.
---

# Write the report

Turn confirmed findings into a submission-ready deliverable. A triager should
not be able to tell an agent wrote it.

## Structure per finding

1. **Title + summary** — one line, precise, no clickbait.
2. **Root cause** — the exact code path (source → sink), not a generic description.
3. **Reproduction steps** — exact request(s) + the marker/control proof from
   `verify-finding`.
4. **Impact** — what an attacker actually gains (data, RCE, account takeover).
5. **CVSS** — `cvss_score` with the correct vector string; do not inflate.
6. **Remediation** — concrete, implementable, framework-appropriate.

## Tools

- `generate_report` — deterministic markdown/JSON report from the findings.
- `cvss_score` — deterministic CVSS v3.1 vector.
- `redact` — strip passwords/keys/tokens/cookies before any output.
- `finding_attach_evidence` — link the redacted, SHA-256-tagged evidence.

## Rules

- Only CONFIRMED findings (passed `adversarial-review`) go in the report.
- No false-positive spam, no "low-hanging fruit" filler.
- Never include raw secrets, API keys, or live session tokens.
- Group by root cause; a report full of duplicates reads as noise.
