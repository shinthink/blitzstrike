# graphw00f

- **Category**: Web / API GraphQL Fingerprinting
- **Risk Level**: 🟡 Medium

---

## Description

GraphQL server fingerprinting tool. It identifies GraphQL implementations and engine-specific behavior to guide follow-up testing and known-issue research.

## Installation

```bash
# Pre-installed on Kali at /opt/graphw00f
# Or install manually:
git clone https://github.com/dolevf/graphw00f.git
cd graphw00f
pip install -r requirements.txt
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-t <url>` / `--target` | Target GraphQL endpoint URL |
| `-d` / `--detect` | Detect mode, scans for GraphQL endpoints |
| `-f` / `--fingerprint` | Fingerprint mode |
| `-o <file>` / `--output-file` | Output results to a file (CSV format) |
| `-r` / `--noredirect` | Do not follow redirections given by 3xx responses |
| `-p <url>` / `--proxy` | HTTP(S) proxy URL |
| `-T <seconds>` / `--timeout` | Request timeout in seconds |
| `-l` / `--list` | List all GraphQL technologies graphw00f can detect |
| `-u <agent>` / `--user-agent` | Custom User-Agent string |
| `-H <header>` / `--header` | Custom header (e.g. `Authorization: Bearer <token>`) |
| `-w <file>` / `--wordlist` | Path to custom GraphQL endpoint wordlist |
| `-v` / `--version` | Print version and exit |

## Common Commands

```bash
# Fingerprint GraphQL endpoint
python3 /opt/graphw00f/main.py -f -t https://target/graphql

# Detect mode — scan for GraphQL endpoints
python3 /opt/graphw00f/main.py -d -t https://target/graphql

# Fingerprint through a proxy with custom timeout
python3 /opt/graphw00f/main.py -f -t https://target/graphql -p http://127.0.0.1:8080 -T 10

# List supported GraphQL technologies
python3 /opt/graphw00f/main.py -l
```

## Notes & Tips

1. Use after discovering a GraphQL endpoint with `katana`, `httpx`, or application routes.
2. Fingerprint results are hints; validate engine-specific vulnerabilities before reporting.
3. Combine with introspection, clairvoyance, and ZAP GraphQL API scan.

---

## Official References

- [graphw00f GitHub](https://github.com/dolevf/graphw00f)

