# Gitleaks

- **Category**: Web / Source and Secret Scanning
- **Risk Level**: 🟢 Low

---

## Description

Gitleaks is a SAST-style CLI tool for finding hardcoded secrets such as passwords, API keys, and tokens in Git repositories, directories, files, and stdin streams. It is useful when source code, deployment bundles, exposed `.git` data, CI artifacts, or downloaded repositories are in scope. For agent workflows, use JSON or SARIF reports and redact findings when sharing output.

## Installation

```bash
sudo apt update
sudo apt install gitleaks

gitleaks --help
gitleaks version
```

## Parameter Reference

| Parameter | Description |
|---------------------|-------------|
| `gitleaks git <repo>` | Scan a local Git repository and its history |
| `gitleaks dir <path>` | Scan directories or files without requiring Git history |
| `gitleaks stdin` | Scan data streamed from stdin |
| `--source <path>` | Source path for older Kali versions that still expose `detect` / `protect` |
| `-c, --config <file>` | Use a custom Gitleaks configuration file |
| `-b, --baseline-path <file>` | Ignore findings already present in a previous report |
| `-f, --report-format <format>` | Report format, such as `json`, `csv`, `junit`, `sarif`, or `template` |
| `-r, --report-path <file>` | Write report output to a file |
| `--redact` | Redact secrets in logs and stdout |
| `--exit-code <n>` | Exit code when leaks are found |
| `--max-target-megabytes <n>` | Skip files larger than the specified size |
| `--log-level <level>` | Set log level |
| `-v, --verbose` | Show verbose scan output |
| `--enable-rule <ids>` | Only enable specific rules by id |
| `--max-decode-depth <n>` | Allow recursive decoding |

## Common Commands

```bash
# Scan the current Git repository including history
gitleaks git -v --redact -f json -r /tmp/gitleaks-git.json .

# Scan a checked-out source directory without Git history
gitleaks dir --redact -f json -r /tmp/gitleaks-dir.json ./source

# Produce SARIF for CI-style reporting
gitleaks git --redact -f sarif -r /tmp/gitleaks.sarif ./repo

# Scan a commit range
gitleaks git --redact --log-opts="--all main..HEAD" -f json -r /tmp/gitleaks-range.json ./repo

# Create a baseline report
gitleaks git --redact -f json -r /tmp/gitleaks-baseline.json ./repo

# Report only findings not already in the baseline
gitleaks git --baseline-path /tmp/gitleaks-baseline.json --redact -f json -r /tmp/gitleaks-new.json ./repo

# Scan piped content
cat /tmp/config.txt | gitleaks stdin --redact -f json -r /tmp/gitleaks-stdin.json
```

## Notes & Tips

1. Current upstream Gitleaks uses `git`, `dir`, and `stdin` as primary scan modes; older Kali packages may still show `detect` and `protect`.
2. Use `--redact` by default so reports can be handled without exposing raw credentials unnecessarily.
3. Use `gitleaks git` for repository history and `gitleaks dir` for extracted archives, web roots, or build artifacts.
4. Treat findings as sensitive evidence even when redacted; filenames and context can still disclose secrets.
5. Use `--baseline-path` to separate pre-existing findings from new leaks in repeated assessments.

---

## Official References

- [Gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [Gitleaks Website](https://gitleaks.io/)
- [Kali gitleaks](https://www.kali.org/tools/gitleaks/)
