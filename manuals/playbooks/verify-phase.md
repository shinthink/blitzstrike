# Verify Phase — turn hypotheses into verdicts (no babysitting)

Use this AFTER detection (run_engagement / run_autonomous returns status DETECTED).
Detection is INPUT. Verification is the work that produces a FINDING.

## Iron rule
A hit is a HYPOTHESIS. Live verification (marker + negative control) is the verdict.
Never report unverified. Sink is not a vulnerability — prove the impact.

## Verdict recipe (per lead)
For EVERY lead, run marker + negative control and record the raw response (SHA-256 tagged):

| Verdict | Condition | Next |
|---|---|---|
| CONFIRMED | marker reflected/read AND control inert | finding_create + evidence + CVSS |
| FALSE_POSITIVE | marker AND control both reflected (indistinguishable) | reject the finding |
| UNCONFIRMED | marker not reflected | refine payload once, then mark |
| BLOCKED | request failed / auth gate / WAF | record required vantage, MOVE ON |

## Tool mapping (call the deterministic verifier, don't eyeball)
- HTTP reflection / injection → `strike_verify` (marker + negative control + WAF bypass auto)
- CWE-22 / path traversal / LFI → `verify_file_read` (marker `/etc/passwd` vs non-existent control)
- DOM-XSS / AJAX interception / JS errors / redirect chains / SSO-token flow → `drive_devtools` (MANDATORY precision layer)
- Before browser precision → `check_mcp` to confirm chrome-devtools-mcp is available

## No-babysitting rules
- Execute every lead until confirmed/blocked — NEVER ask "should I continue?".
- confirmed → escalate (list_chains + chain_links) and follow where the chain leads NOW, not "next phase".
- blocked → note the vantage and continue to the next lead; a hard block is not the end.
- Stop only: destructive/DoS consent, external block (OTP/creds), or COMPLETE.

## Deliverable
When every lead is confirmed / blocked / false-positive → `generate_report` with all findings
(each carrying evidence). The report is the output — never a hand-written surface map.
