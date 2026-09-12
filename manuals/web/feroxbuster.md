# feroxbuster

- **Category**: Web / Directory Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

A fast, simple, recursive content discovery tool written in Rust. Supports automatic recursive subdirectory discovery, multiple wordlists, response filtering, link extraction, and flexible output options. Fast with low false-positive rates.

## Installation

```bash
sudo apt install feroxbuster
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-u URL` | Target URL |
| `-w FILE` | Wordlist file |
| `-x EXT` | File extensions (comma-separated) |
| `-t N` | Concurrent threads (default 50) |
| `-d N` | Recursion depth (default 4) |
| `--no-recursion` | Do not scan recursively |
| `-s STATUS` | Include only these status codes in results |
| `-C STATUS` | Exclude status codes |
| `-S SIZE` | Filter by response size |
| `-H HEADER` | Add request headers |
| `-b COOKIE` | Cookie |
| `-k` | Disables TLS certificate validation |
| `-o FILE` | Output file |
| `--json` | JSON output |
| `-r` | Follow redirects |
| `--rate-limit N` | Requests per second per directory being scanned (default: 0, no limit) |
| `--auto-tune` | Automatically lower scan rate on errors |
| `--auto-bail` | Automatically stop on excessive errors |

## Common Commands

```bash
# Basic scan
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Specify extensions
feroxbuster -u http://target.com -w wordlist.txt -x php,html,txt,bak,zip

# HTTPS (ignore certificate)
feroxbuster -u https://target.com -w wordlist.txt -k

# Limit recursion depth
feroxbuster -u http://target.com -w wordlist.txt -d 2

# Filter 404 and 403
feroxbuster -u http://target.com -w wordlist.txt -C 404,403

# With authentication
feroxbuster -u http://target.com -w wordlist.txt -H "Authorization: Bearer TOKEN"
feroxbuster -u http://target.com -w wordlist.txt -b "session=abc123"

# Output to file
feroxbuster -u http://target.com -w wordlist.txt -o /tmp/ferox_results.txt

# Rate limiting (to avoid triggering WAF)
feroxbuster -u http://target.com -w wordlist.txt --rate-limit 100

# Use proxy
feroxbuster -u http://target.com -w wordlist.txt --proxy http://127.0.0.1:8080
```

## Notes & Tips

1. feroxbuster is significantly faster than gobuster for recursive scanning — use it when deep directory traversal is needed.
2. The `--auto-tune` flag automatically adjusts request rate when an excessive number of errors are encountered — reduces false positives from overwhelmed servers.
3. Use `--filter-status 301,302` to exclude redirects and `--filter-size <n>` to exclude responses with a specific byte count (useful for filtering "not found" pages that return 200).
4. Resume interrupted scans with `--resume-from <state-file>` — feroxbuster saves state automatically when interrupted with Ctrl+C.
5. Combine with hakrawler — feroxbuster brute-forces unknown paths, hakrawler discovers paths already linked from the application.

---

## Official References

- [feroxbuster GitHub](https://github.com/epi052/feroxbuster)
- [feroxbuster Documentation](https://epi052.github.io/feroxbuster-docs/overview/)
