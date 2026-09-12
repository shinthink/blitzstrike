---
name: verify-finding
description: Use when you have a hypothesis and need to prove it is a real, exploitable finding before reporting it. Live verification with a marker + negative control — never report an unverified hypothesis as a finding.
---

# Verify a finding (marker + negative control)

"Detection is not proof." A static hit or a scan match is a hypothesis until it
is live-verified with a distinguishable marker and an inert negative control.

## Procedure

1. **Pick the right verifier.**
   - Live HTTP → `strike_verify` (sends a payload, checks for a unique marker).
   - Browser/DOM (XSS, auth flows) → `browser_validate`.

2. **Marker, not echo.** Use a unique, nonce-like marker (`blitzstrike-<rand>`)
   that cannot be a benign echo. If the response reflects it, that is the signal.

3. **Negative control.** Send a payload that is structurally similar but MUST NOT
   trigger (a wrong param, a harmless value). If the control ALSO reflects the
   marker, it is a `false_positive` — the app echoes everything, not exploitable.

4. **Interpret.**
   - Marker reflected + control inert → `verdict=confirmed`, attach evidence.
   - Marker reflected + control also reflected → `false_positive`, reject.
   - Nothing → retry once, then `NEEDS_MORE_EVIDENCE`.

5. **Record.** `finding_attach_evidence` (redacted, SHA-256 tagged) +
   `finding_transition` to validated/rejected. Use `redact` on any secret before
   it is persisted.

## Pitfalls

- Never verify by "looks right" — the marker/control pair is the only proof.
- A blind RCE without a callback channel: tunnel the callback (public tunnel,
  no local IP) and observe it arrive — that is the proof.
- Keep evidence redacted; raw secrets must never be persisted.
