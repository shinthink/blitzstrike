# subfinder

- **Category**: Information Gathering / Subdomain Discovery
- **Risk Level**: 🟢 Low

---

## Description

A passive subdomain discovery tool by ProjectDiscovery (same team as nuclei). Queries 40+ public data sources — VirusTotal, Shodan, Censys, Certificate Transparency logs, and more — without sending any packets to the target. Fast and pipeline-friendly; widely used in the recon phase to build an initial target inventory before active scanning.

## Installation

```bash
sudo apt install subfinder
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Domains to find subdomains for |
| `-dL <file>` | File containing list of domains (one per line) |
| `-o <file>` | Output file |
| `-oJ` | Write output in JSONL(ines) format |
| `-t <n>` | Concurrent goroutines for resolving (default 10) |
| `-silent` | Show only subdomains in output |
| `-recursive` | Use only sources that can handle subdomains recursively |
| `-all` | Use all sources for enumeration (slow) |
| `-v` | Show verbose output |
| `-pc <file>` | Provider config file (default: ~/.config/subfinder/provider-config.yaml) |
| `-s <sources>` | Specify specific sources to use (comma-separated) |

## Common Commands

```bash
# Basic subdomain enumeration
subfinder -d example.com

# Save results to file
subfinder -d example.com -o subdomains.txt

# Enumerate multiple domains from a file
subfinder -dL domains.txt -o all-subdomains.txt

# Use all sources (requires API keys for some)
subfinder -d example.com -all -v

# JSON output for piping to other tools
subfinder -d example.com -oJ | jq '.host'

# Chain with httpx to probe live subdomains
subfinder -d example.com -silent | httpx -silent

# Full recon pipeline: discover → probe → scan
subfinder -d example.com -silent | httpx -silent | nuclei -t cves/
```

## Notes & Tips

1. subfinder is fully passive — it does not send packets to the target, only queries public data sources.
2. Register API keys for VirusTotal, Shodan, Censys, etc. in `~/.config/subfinder/provider-config.yaml` to significantly increase coverage.
3. Combine with `amass` for maximum coverage: amass handles active DNS techniques, subfinder covers passive sources.
4. The `-silent` flag is essential for pipeline use — suppresses progress output and leaves only results.
5. After subdomain enumeration, always probe with `httpx` to identify live HTTP services before scanning.

---

## Official References

- [subfinder (GitHub)](https://github.com/projectdiscovery/subfinder)
- [Kali subfinder](https://www.kali.org/tools/subfinder/)
