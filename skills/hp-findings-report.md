---
name: findings-report
description: Use to turn raw output from one or more other skills into a single ranked, remediation-ready report. Run this last, after any combination of the other skills, to synthesize findings/*.json and findings/*.txt into something a developer or stakeholder can actually act on.
---

# Findings report

Raw tool output is not a deliverable. This skill's whole job is compression and prioritization.

## Workflow

1. **Collect everything under `findings/`** from whichever skills ran — gitleaks/trufflehog JSON, osv-scanner/npm-audit output, semgrep/bandit results, sqlmap/nuclei/zap output, checkov/trivy/prowler output, slither/mythril output, manual notes from `web-app-pentest`/`api-security-test`/`auth-session-security`/`business-logic-fuzzing`.

2. **Deduplicate across tools.** The same underlying issue often surfaces from multiple angles (a hardcoded secret caught by both gitleaks and semgrep's secrets ruleset; a missing auth check caught by both sast-code-review and api-security-test's manual BOLA testing). Merge these into one finding rather than reporting duplicates.

3. **Rank by actual severity, not tool-reported severity alone.** Reweight based on:
   - **Exploitability** — is there a working PoC/reproduction, or is this theoretical pattern-matching?
   - **Blast radius** — does this expose one record or the whole database; one user's session or an auth bypass for everyone?
   - **Reachability** — is the vulnerable code path actually reachable by an untrusted user, or gated behind something else?

4. **Write the report** using this structure (see `templates/finding-report.md` for the literal template):
   - **Summary** — one paragraph: overall risk posture, count of findings by severity, the 1-3 things that matter most.
   - **Critical / High findings** — full detail each: what it is, proof (request/response, code location, PoC), impact, fix, effort estimate.
   - **Medium / Low findings** — condensed table: finding, location, fix, one line each.
   - **Informational** — things worth knowing but not urgent (forgotten staging subdomain, verbose error messages, missing security headers with no direct exploit).
   - **What was tested** — list which skills ran, against what scope, so the reader knows what this report does and doesn't cover. A clean scan of 5 skills is a very different statement than a clean scan of 1.

5. **Lead with fixes, not just problems.** Every finding needs a concrete next action — a code diff, a config change, an upgrade command, not just "this is vulnerable."

## Output

`findings/<timestamp>/report.md` — the final deliverable. This is what gets shown to the user; raw tool JSON stays as backing evidence, not the primary output.

## Notes

- If zero findings came back across every skill that ran, say that plainly and list what was tested — "clean" is a real, useful result, not something to pad with speculative low-severity noise to look thorough.
- Never redact away the specifics a developer needs to reproduce and fix an issue — redact only secret values themselves (truncate keys/tokens), not the surrounding context.
