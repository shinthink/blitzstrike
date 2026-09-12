---
name: business-logic-fuzzing
description: Use for the vulnerability classes automated scanners structurally cannot find — race conditions, workflow/state-machine bypass, price or quantity manipulation, and abuse of multi-step flows. This is the highest-value, most manual skill in the repo; run it after the automated skills, informed by what they revealed about the app's structure.
---

# Business logic & fuzzing

No scanner can find these because they require understanding what the app is *supposed* to do before you can find where it does something else. Slow down for this one.

## Prerequisites

- Whatever HTTP tooling lets you fire concurrent/rapid requests (`curl` in a loop with `&`, a small script, or a load-testing tool like `hey`/`vegeta` repurposed for concurrency testing)
- A real understanding of the app's intended workflow — read the code or use it as a normal user first

## Workflow

1. **Map every multi-step flow** — checkout, signup, password reset, any wizard/form-across-pages, any approval/review process. For each, ask: what state does the server expect at each step, and is that state actually enforced, or just assumed from the client's behavior?

2. **Race conditions** — any operation that reads a value, does a check, then writes based on that check (balance check before withdrawal, coupon-use check before redemption, inventory check before purchase) is a candidate. Fire the same request concurrently and see if the check can be bypassed by winning the race:
   ```bash
   for i in {1..20}; do
     curl -s -X POST https://target/api/redeem-coupon -H "Authorization: Bearer $TOKEN" -d '{"code":"SAVE50"}' &
   done
   wait
   ```
   A single-use coupon redeemed 20 times, or a balance going negative, confirms a TOCTOU (time-of-check-to-time-of-use) bug. This is one of the highest-value bug classes in the entire repo and the one automated scanners are worst at finding.

3. **Workflow/state-machine bypass** — can a later step in a multi-step flow be called directly, skipping earlier steps? (e.g., calling the "confirm order" endpoint without ever calling "add payment method"; calling an admin-approval endpoint as the requester themselves; skipping email verification by calling the post-verification endpoint directly with a guessed/replayed token.)

4. **Price/quantity/parameter manipulation** — for anything involving money or countable resources, test:
   - Negative quantities (`quantity: -1` might credit instead of debit)
   - Zero or fractional values where only positive integers are expected
   - Client-supplied price/total fields that the server trusts instead of recalculating server-side
   - Currency/unit confusion (submitting a value in cents where the server expects dollars, or vice versa)
   - Quantity/discount stacking that shouldn't be allowed (applying the same one-time discount via two different code paths)

5. **Idempotency abuse** — for any endpoint meant to be called once per logical action (payment capture, referral bonus grant, one-time signup bonus), test whether replaying the exact same request with the same idempotency key/token produces the effect multiple times.

6. **Trust boundary confusion** — anywhere the server trusts a value that should be recomputed server-side: client-reported "am I an admin" flags, client-computed hashes/checksums the server should verify, timestamps used for business logic that the client controls.

## Output

Per finding: the flow, the exact sequence of requests that breaks it, what the correct behavior should have been, business impact (this is the skill where "impact" often means real financial loss, not just data exposure — say so explicitly), severity.

## Notes

- This skill benefits enormously from `sast-code-review` findings — if static analysis flagged a check-then-act pattern in the code, that's a direct pointer to where to focus race-condition testing here.
- Findings here are usually the hardest to explain to a non-security audience because there's no CVE, no scanner flag, just "if you do A then B fast enough, the app loses track of state." Always include a concrete, reproducible sequence of requests — abstract descriptions don't land.
