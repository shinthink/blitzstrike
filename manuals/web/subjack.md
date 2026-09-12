# subjack

- **Category**: Web / Subdomain Takeover
- **Risk Level**: 🟡 Medium

---

## Description

Detects subdomain takeover vulnerabilities at scale by checking CNAME records for subdomains pointing to deprovisioned cloud services. Verifies whether the underlying resource (AWS S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Pantheon, etc.) has been released and can be claimed by an attacker. Supports concurrent checking with configurable thread count for large subdomain lists. Written in Go.

## Installation

```bash
sudo apt install subjack
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Single domain to check |
| `-w <file>` | Path to wordlist containing subdomains to check (one per line) |
| `-c <path>` | Path to configuration file (default: `/usr/share/subjack/fingerprints.json`) |
| `-t <num>` | Number of concurrent threads (default: 10) |
| `-timeout <seconds>` | Seconds to wait before connection timeout (default: 10) |
| `-o <file>` | Output results to file (use `.json` extension for JSON output) |
| `-ssl` | Force HTTPS connections (may increase accuracy) |
| `-a` | Find hidden gems by sending requests to every URL |
| `-m` | Flag the presence of a dead record, but valid CNAME entry |
| `-v` | Display more information per request |

## Common Commands

```bash
# Check subdomains from a file for takeover vulnerabilities
subjack -w /tmp/subdomains.txt -t 50 -timeout 30 -o /tmp/takeover.txt -ssl

# Check a single domain
subjack -d sub.target.com -ssl

# Use a custom fingerprints configuration file
subjack -w /tmp/subdomains.txt -c /path/to/fingerprints.json -t 50 -ssl -o /tmp/takeover.txt

# Flag dead CNAME records with valid entries
subjack -w /tmp/subdomains.txt -m -t 50 -ssl -o /tmp/dead_cnames.txt

# Send requests to all URLs (not just those with CNAMEs)
subjack -w /tmp/subdomains.txt -a -t 50 -ssl -o /tmp/all_results.txt

# High concurrency scan with verbose output
subjack -w /tmp/subdomains.txt -t 200 -ssl -v -o /tmp/takeover.txt

# Pipe subdomains from subfinder
subfinder -d target.com -silent | tee /tmp/subs.txt && \
  subjack -w /tmp/subs.txt -t 100 -ssl -o /tmp/takeover.txt
```

## Notes & Tips

1. Combine with subdomain enumeration tools (`subfinder`, `amass`, `findomain`) to generate comprehensive input lists before running subjack.
2. Use `-d` for quick single-domain checks during manual verification; use `-w` for bulk scanning.
3. The `-c` flag specifies the fingerprints configuration file that defines which services are checked. The default at `/usr/share/subjack/fingerprints.json` covers common providers.
4. The `-m` flag identifies dead CNAME records that still have valid entries — useful for finding potentially exploitable dangling records.
5. High thread counts (`-t 200+`) significantly speed up scanning on large lists but may trigger rate limiting or IP blocking by DNS resolvers or target services.

---

## Official References

- [Subjack GitHub](https://github.com/haccer/subjack)
- [Kali Tools — subjack](https://www.kali.org/tools/subjack/)
