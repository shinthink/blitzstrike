---
name: full-security-audit
description: Use when the user asks for a full security audit, pentest, vulnerability scan, or "is this safe to ship" check without specifying a narrower scope. The master playbook — chains recon through reporting across whatever surfaces the target actually has (skip skills that don't apply, e.g. no mobile-app-scan if there's no mobile app).
---

# Full security audit

This is the "just audit the whole thing" entry point. It chains every other skill in this repo into one pass, in an order chosen so each stage informs the next, and ends with a single ranked report.

## Step 0 — scope the target

Before running anything, establish:
- What is this? (a source repo, a deployed web app, an API, a container image, an infra/IaC repo, a mobile app, a set of smart contracts — usually some combination)
- What's authorized? (own repo/infra — fine by default; anything that looks like it belongs to someone else — confirm before proceeding)
- What environment is safe to actively test? (staging is generally fine for aggressive testing; production usually limits you to passive/low-impact checks unless the user explicitly says otherwise)

Skip any skill below that doesn't apply to what you were given — a static-only source repo with no deployed instance skips `web-app-pentest`, `dast-active-scan`, `network-service-scan`, and `tls-transport-security` entirely; a pure frontend repo skips `smart-contract-audit`; and so on. Don't force-run a skill against a target it doesn't fit.

## Step 1 — recon (always first, if there's a live target)

Run [`attack-surface-recon`](../attack-surface-recon/SKILL.md) against any domain/host. This produces the target list every subsequent live-testing skill consumes. If the target is source-only (no deployed instance to point at), skip straight to step 2.

## Step 2 — source-level checks (fast, run against any codebase)

In parallel/any order:
- [`secrets-scan`](../secrets-scan/SKILL.md) — always run this one, it's the highest signal-to-effort ratio in the repo
- [`dependency-audit`](../dependency-audit/SKILL.md)
- [`sast-code-review`](../sast-code-review/SKILL.md)
- [`ci-cd-pipeline-security`](../ci-cd-pipeline-security/SKILL.md) if the repo has CI config
- [`container-image-scan`](../container-image-scan/SKILL.md) if there's a Dockerfile/image
- [`iac-cloud-posture`](../iac-cloud-posture/SKILL.md) (static half) if there's Terraform/K8s/CloudFormation
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) if there are Solidity/Vyper contracts

## Step 3 — live-target checks (only against a running target you're authorized to actively test)

In this order, since each informs the next:
1. [`network-service-scan`](../network-service-scan/SKILL.md) and [`tls-transport-security`](../tls-transport-security/SKILL.md) — infra layer
2. [`dast-active-scan`](../dast-active-scan/SKILL.md) — automated broad sweep to find where to focus
3. [`auth-session-security`](../auth-session-security/SKILL.md) — do this before the next two, since a broken auth layer changes what's testable
4. [`web-app-pentest`](../web-app-pentest/SKILL.md) and/or [`api-security-test`](../api-security-test/SKILL.md) depending on whether the target is a web app, an API, or both
5. [`mobile-app-scan`](../mobile-app-scan/SKILL.md) if a mobile build exists
6. [`iac-cloud-posture`](../iac-cloud-posture/SKILL.md) (live half) if the target is deployed to a cloud account you have read access to

## Step 4 — the manual pass

[`business-logic-fuzzing`](../business-logic-fuzzing/SKILL.md) — do this last and don't skip it. It's the slowest skill and the one most informed by everything you learned in steps 1-3 (what the app's real workflows are, where checks exist, where they might not).

## Step 5 — report

[`findings-report`](../findings-report/SKILL.md) — synthesize everything under `findings/` into one ranked report using `templates/finding-report.md`. This is the actual deliverable; nothing before this step should be shown to the user as a final answer on its own.

## Optional — agentic deep pass

For a target that warrants it (pre-launch, handling real user funds/data, or just wanting a second independent pass), [strix](https://github.com/usestrix/strix) is a good complement: an autonomous AI pentesting agent that runs its own recon→exploit→validate loop and produces working PoCs. Not a replacement for the structured pass above, but a useful "have a second, differently-built system try to break it" layer:

```bash
strix --target <path-or-url>
```

## Notes for whichever agent is running this

- Don't run every skill blindly — think about what actually applies, same as a human pentester would scope an engagement before starting.
- Time-box appropriately to what was asked. "Quick check before I push this" and "full audit before we handle real customer payments" are different requests — say which one you're doing.
- Surface findings as you go if something critical turns up (an exposed secret, a live RCE) rather than waiting until the final report to mention it.
