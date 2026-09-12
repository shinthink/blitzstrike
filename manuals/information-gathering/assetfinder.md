# assetfinder

- **Category**: Information Gathering / Subdomain Discovery
- **Risk Level**: 🟢 Low

---

## Description

A fast passive subdomain discovery tool by Tom Hudson (tomnomnom). Queries certificate transparency logs, DNS records, the Wayback Machine, and multiple threat intelligence platforms to discover domains and subdomains associated with a target. Lightweight and pipeline-friendly — outputs one subdomain per line, designed for use with httpx, nuclei, and other tools.

## Installation

```bash
sudo apt install assetfinder
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<domain>` | Target domain to find subdomains for |
| `-subs-only` | Only show unique subdomains (strip parent domains) |

## Common Commands

```bash
# Find all associated domains and subdomains
assetfinder example.com

# Show only subdomains (no parent domain variations)
assetfinder -subs-only example.com

# Save to file
assetfinder -subs-only example.com > subdomains.txt

# Chain with httpx to probe live subdomains
assetfinder -subs-only example.com | httpx -silent

# Chain with nuclei for automated scanning
assetfinder -subs-only example.com | httpx -silent | nuclei -t cves/

# Combine with subfinder for broader coverage
{ assetfinder -subs-only example.com; subfinder -d example.com -silent; } | sort -u | httpx -silent
```

## Notes & Tips

1. assetfinder is faster and simpler than subfinder/amass but queries fewer sources — use it as a quick first pass or supplement.
2. `-subs-only` removes unrelated domain variations and focuses output on actual subdomains of the target.
3. The tool doesn't require API keys — it works entirely through public data sources.
4. Combine with subfinder and amass for maximum subdomain coverage: all three query different sets of sources.
5. Output is not deduplicated — pipe through `sort -u` when combining multiple tools.

---

## Official References

- [assetfinder (GitHub)](https://github.com/tomnomnom/assetfinder)
- [Kali assetfinder](https://www.kali.org/tools/assetfinder/)
