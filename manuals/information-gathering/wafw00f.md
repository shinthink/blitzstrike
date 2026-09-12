# wafw00f

- **Category**: Information Gathering / Web Fingerprinting
- **Risk Level**: 🟢 Low

---

## Description

A tool specifically designed to detect Web Application Firewalls (WAF), supporting identification of 200+ WAF products. Knowing whether the target has a WAF deployed and what type it is before penetration testing helps in selecting an appropriate bypass strategy.

## Installation

```bash
sudo apt install wafw00f
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-a` / `--findall` | Find all WAFs matching signatures, do not stop at first one |
| `-r` / `--noredirect` | Do not follow redirections given by 3xx responses |
| `-t WAF` / `--test WAF` | Test against a specific WAF |
| `-p PROXY` / `--proxy PROXY` | Use an HTTP proxy to perform requests |
| `-v` / `--verbose` | Enable verbosity (multiple -v increases verbosity) |
| `-i FILE` / `--input-file FILE` | Read target URLs from file |
| `-o FILE` / `--output FILE` | Write output to csv, json, or text file depending on extension |
| `-f FORMAT` / `--format FORMAT` | Output format (json/csv/text) |
| `-l` / `--list` | List all WAFs that WAFW00F is able to detect |
| `-V` | Print version and exit |

## Common Commands

```bash
# Basic detection
wafw00f http://target.com

# HTTPS
wafw00f https://target.com

# Detect all possible WAFs
wafw00f -a https://target.com

# Batch detection
wafw00f -i urls.txt

# JSON output
wafw00f https://target.com -o /tmp/waf_result.json -f json

# Use proxy
wafw00f https://target.com -p http://127.0.0.1:8080
```

## Notes & Tips

1. After detecting a WAF, tune follow-up tools instead of immediately increasing scan intensity.
2. For sqlmap, start with low-risk tamper scripts such as `--tamper=space2comment` and validate each result manually.
3. For ffuf and other fuzzers, reduce concurrency and add random delay to avoid rate limiting.
4. Manual checks can vary User-Agent and forwarding headers such as `X-Forwarded-For: 127.0.0.1`, but treat bypass results as target-specific.

---

## Official References

- [wafw00f GitHub](https://github.com/EnableSecurity/wafw00f)
