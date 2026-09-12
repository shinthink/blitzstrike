# Findomain

- **Category**: Information Gathering / Subdomain Discovery
- **Risk Level**: 🟢 Low

---

## Description

A fast, cross-platform subdomain enumeration tool written in Rust. Queries multiple certificate transparency logs and APIs (crt.sh, Certspotter, Facebook CT, VirusTotal, Sublist3r, etc.) for passive subdomain discovery. Supports real-time monitoring mode for continuous subdomain detection, HTTP/S probing, screenshot capture, and output in multiple formats. Pipeline-friendly and significantly faster than many Python-based alternatives.

## Installation

```bash
sudo apt install findomain
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-t <domain>` | Target host |
| `-f <file>` | Use a list of subdomains written in a file as input |
| `-o` | Write to an automatically generated output file |
| `-u <file>` | Write all results for a target or list of targets to a specified filename |
| `-q` | Remove informative messages but show fatal errors or subdomains not found |
| `-r` / `--resolved` | Show/write only resolved subdomains |
| `--http-status` | Check HTTP/S status of discovered subdomains |
| `--threads <n>` | Number of threads for lightweight tasks such as IP discovery and HTTP checks |
| `-i` | Show/write the IP address of resolved subdomains |
| `--monitoring-flag` | Activate Findomain monitoring mode |
| `-w <file>` | Wordlist for subdomain bruteforce (enables bruteforce mode) |

## Common Commands

```bash
# Basic subdomain enumeration
findomain -t example.com

# Save results to a user-specified file (quiet mode)
findomain -t example.com -q -u subdomains.txt

# Enumerate with DNS resolution filtering
findomain -t example.com -r -u alive.txt

# Show subdomains with IP addresses
findomain -t example.com -i

# Check HTTP status of discovered subdomains
findomain -t example.com --http-status

# Enumerate multiple domains from a file
findomain -f domains.txt -u all-subdomains.txt

# Chain with httpx for further probing
findomain -t example.com -q | httpx -silent
```

## Notes & Tips

1. Findomain is purely passive — it queries public data sources and never sends packets to the target.
2. Compared to subfinder, Findomain focuses on certificate transparency sources and is faster for large-scale enumeration.
3. Use `-r` to immediately filter for subdomains that resolve, reducing false positives before passing to downstream tools.
4. The monitoring mode (`--monitoring-flag`) detects newly appearing subdomains over time, useful for continuous asset discovery.
5. Combine with `subfinder` for maximum coverage — each tool queries different data sources.

---

## Official References

- [Findomain (GitHub)](https://github.com/Findomain/Findomain)
- [Kali Findomain](https://www.kali.org/tools/findomain/)
