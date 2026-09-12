# FinalRecon

- **Category**: Information Gathering / Web Reconnaissance
- **Risk Level**: 🟢 Low

---

## Description

A fast Python-based web reconnaissance tool with a modular structure. Performs header analysis, SSL certificate inspection, WHOIS lookups, DNS enumeration, subdomain discovery, web crawling, Wayback Machine URL retrieval, and port scanning in a single run. Useful for comprehensive initial web reconnaissance before deeper testing.

## Installation

```bash
sudo apt install finalrecon
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--url <url>` | Target URL |
| `--full` | Full recon |
| `--headers` | Header information |
| `--sslinfo` | SSL/TLS certificate information |
| `--whois` | WHOIS lookup |
| `--crawl` | Crawl target |
| `--dns` | DNS enumeration |
| `--sub` | Sub-domain enumeration |
| `--ps` | Fast port scan |
| `--wayback` | Wayback URLs |
| `-T <n>` | Request timeout (seconds) |
| `-w <wordlist>` | Path to wordlist (default: wordlists/dirb_common.txt) |
| `--dir` | Directory search |
| `-nb` | Hide banner |
| `-dt <n>` | Directory enumeration threads |
| `-pt <n>` | Port scan threads |
| `-r` | Allow HTTP redirects |
| `-s` | Toggle SSL verification |
| `-sp <port>` | SSL port |
| `-d <dns>` | Custom DNS servers |
| `-e <ext>` | File extensions for directory search |
| `-o <format>` | Export format (txt/xml/csv) |
| `-cd <dir>` | Change export directory |
| `-k <key>` | Add API key |

## Common Commands

```bash
# Full reconnaissance (all modules)
finalrecon --url http://example.com --full

# Header and SSL analysis only
finalrecon --url http://example.com --headers --sslinfo

# DNS + subdomain enumeration
finalrecon --url http://example.com --dns --sub

# Combine web crawling and Wayback URLs
finalrecon --url http://example.com --crawl --wayback

# Port scan + WHOIS
finalrecon --url http://example.com --ps --whois
```

## Notes & Tips

1. finalrecon is a good first-pass tool — run it early to get an overview of the target's infrastructure before using specialized tools.
2. `--full` covers all modules but takes longer; use targeted flags for speed.
3. For deeper subdomain enumeration, pair finalrecon results with subfinder and amass.
4. SSL certificate data (--sslinfo) often reveals related domains in Subject Alternative Names (SANs).
5. Wayback Machine URLs (--wayback) frequently expose old API endpoints, admin panels, and backup files.

---

## Official References

- [finalrecon (GitHub)](https://github.com/thewhiteh4t/FinalRecon)
- [Kali finalrecon](https://www.kali.org/tools/finalrecon/)
