# TruffleHog

- **Category**: Information Gathering / Secret Scanning
- **Risk Level**: 🟡 Medium

---

## Description

Scans git repositories, filesystems, S3 buckets, and CI/CD systems for leaked secrets including API keys, passwords, tokens, and private keys. Uses both regex patterns and entropy analysis to detect secrets, and verifies discovered credentials against live services when possible. Supports scanning full git history to find secrets that were committed and later removed.

## Installation

```bash
sudo apt install trufflehog
# Or download the latest binary from GitHub releases
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `git <repo_url>` | Scan a git repository (local path or remote URL) |
| `filesystem <path>` | Scan a filesystem path |
| `s3` | Scan S3 buckets |
| `github --org <org>` | Scan all repositories in a GitHub organization |
| `gitlab --group <group>` | Scan all repositories in a GitLab group |
| `docker --image <image>` | Scan a Docker image |
| `syslog` | Scan syslog |
| `--json` | JSON output |
| `--no-verification` | Skip live credential verification |
| `--include-detectors <list>` | Comma-separated list of detector types to include |
| `--exclude-detectors <list>` | Comma-separated list of detector types to exclude |
| `--since-commit <hash>` | Scan commits after this commit hash |
| `--branch <name>` | Scan a specific branch |
| `--results <filter>` | Filter output by result type: `verified`, `unknown`, `unverified` |
| `--concurrency <n>` | Number of concurrent workers |

## Common Commands

```bash
# Scan a remote git repository (full history)
trufflehog git https://github.com/target-org/target-repo.git

# Scan a local git repository
trufflehog git file:///path/to/repo

# Scan filesystem directory
trufflehog filesystem /path/to/project

# Scan all repos in a GitHub organization
trufflehog github --org target-org --token $GITHUB_TOKEN

# JSON output for automation
trufflehog git https://github.com/target-org/target-repo.git --json > /tmp/secrets.json

# Show only verified (confirmed active) secrets
trufflehog git https://github.com/target-org/target-repo.git --results verified

# Scan only recent commits
trufflehog git https://github.com/target-org/target-repo.git --since-commit abc123

# Skip live verification (faster, quieter)
trufflehog git https://github.com/target-org/target-repo.git --no-verification
```

## Notes & Tips

1. Verified results indicate that trufflehog confirmed the credential is still active by testing it against the live service — these are critical findings requiring immediate remediation.
2. Scan git repositories with full history by default — secrets committed and later deleted are still recoverable from git history and remain exploitable.
3. Use `--json` output for integration with CI/CD pipelines and automated reporting.
4. For large organizations, use `github --org` with a personal access token to scan all repositories systematically.
5. Pair with manual review: high-entropy strings may produce false positives — validate findings before including them in reports.

---

## Official References

- [TruffleHog (GitHub)](https://github.com/trufflesecurity/trufflehog)
- [Kali trufflehog](https://www.kali.org/tools/trufflehog/)
