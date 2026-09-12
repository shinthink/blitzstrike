---
name: secrets-scan
description: Use when you need to find leaked API keys, tokens, passwords, or credentials in a git repo — including history, not just the current working tree. Run this before every push to a new public repo and as a standing part of full-security-audit.
---

# Secrets scan

Leaked secrets are the single highest-signal, lowest-effort finding in any audit — a real key found here is an immediate, unambiguous fix. Run both tools; they catch different things.

## Prerequisites

- `gitleaks`, `trufflehog` (see `TOOLS.md`)
- A local clone of the target repo (full history, not a shallow clone — `git clone` without `--depth`)

## Workflow

1. **Full history scan with gitleaks** — pattern-based, fast, good default ruleset:
   ```bash
   gitleaks detect --source . --report-format json --report-path findings/gitleaks.json -v
   ```

2. **Verified scan with trufflehog** — actively verifies credentials against the live provider API where possible, which kills most false positives:
   ```bash
   trufflehog git file://. --json > findings/trufflehog.json
   ```
   For anything not in git (local `.env` files, uploaded artifacts, cloud storage buckets you own):
   ```bash
   trufflehog filesystem . --json > findings/trufflehog-fs.json
   ```

3. **Triage**: trufflehog's `Verified: true` results are confirmed live credentials — treat as critical, rotate immediately regardless of whether the repo is private. Gitleaks findings without trufflehog verification still need eyes-on review; check for test fixtures, example configs, and placeholder values (`sk-xxxxx`, `changeme`) before flagging as real.

4. **If a real secret is found in history**: rotating the credential is mandatory and sufficient — rewriting git history (`git filter-repo` / BFG) is optional cleanup *after* rotation, not a substitute for it. A secret that's ever been pushed should be treated as burned.

5. **Check CI/CD and deployment configs separately** — `.github/workflows/*.yml`, `Dockerfile`, `docker-compose.yml`, IaC files. These commonly hardcode credentials that scanners miss if they're not committed to the default branch:
   ```bash
   gitleaks detect --source . --log-opts="--all" --report-path findings/gitleaks-all-branches.json
   ```

## Output

`findings/gitleaks.json`, `findings/trufflehog.json` — feed straight into `findings-report`. Any `Verified: true` result is a stop-the-line item, not a backlog ticket.

## Notes

- Both tools support pre-commit hooks (`gitleaks protect --staged`) — recommend this to the user as a permanent fix once the initial sweep is clean, not just a one-time scan.
- Don't print full secret values in chat or in the report — truncate to first/last 4 characters when confirming a finding with the user.
