---
name: dast-active-scan
description: Use for automated black-box scanning of a live target with ZAP and nuclei — the broad-coverage automated sweep that complements the targeted manual testing in web-app-pentest and api-security-test. Good as a fast first pass or a final coverage check before shipping.
---

# DAST — automated active scan

Breadth over depth: run known-vulnerability templates and an automated crawler+scanner against every reachable endpoint, then hand promising hits to `web-app-pentest`/`api-security-test` for manual confirmation.

## Prerequisites

- `nuclei` with an up-to-date template set, `OWASP ZAP`
- A target URL, ideally with the endpoint list from `attack-surface-recon` already in hand

## Workflow

1. **Update nuclei templates first** — this tool is only as good as its template freshness:
   ```bash
   nuclei -update-templates
   ```

2. **Run a safe, broad nuclei pass** against the live host list:
   ```bash
   nuclei -l findings/live-hosts.txt -severity medium,high,critical -o findings/nuclei.txt
   ```
   For a single known target with more aggressive coverage (only against something you're sure is safe to actively probe):
   ```bash
   nuclei -u https://target.example.com -tags cve,exposure,misconfig,default-login -o findings/nuclei-deep.txt
   ```

3. **ZAP baseline scan** (passive, safe for prod — spiders the app and checks passive rules only, no active attack payloads sent):
   ```bash
   docker run -v $(pwd)/findings:/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
     -t https://target.example.com -J zap-baseline.json -r zap-baseline.html
   ```

4. **ZAP full active scan** (sends real attack payloads — injection, XSS probes, etc. Only run against staging/environments you're certain are safe to actively attack, never unannounced against prod):
   ```bash
   docker run -v $(pwd)/findings:/zap/wrk/:rw -t zaproxy/zap-stable zap-full-scan.py \
     -t https://staging.example.com -J zap-full.json -r zap-full.html
   ```

5. **Triage nuclei/ZAP output for false positives before reporting.** Template-based scanners are noisy — a "possible SQLi" or "possible XSS" hit from an automated tool is a lead, not a confirmed finding. Take anything medium+ severity and manually verify it using the relevant technique from `web-app-pentest` before including it in the final report as confirmed rather than "needs verification."

## Output

`findings/nuclei.txt`, `findings/zap-baseline.json` (+html), `findings/zap-full.json` (+html) if run. Split the report into "confirmed" (manually verified) vs. "flagged, needs review" (raw scanner output) — don't blur the two.

## Notes

- Full active scans are noisy on the target (real traffic volume, real attack payloads) — always confirm with the user which environment is safe to point this at before running step 4.
- This skill is breadth; `web-app-pentest` and `api-security-test` are depth. Run this first to find where to focus, or last as a coverage check after manual testing — either order works, just don't treat this alone as a complete pentest.
