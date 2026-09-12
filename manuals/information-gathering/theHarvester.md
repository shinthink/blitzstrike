# theHarvester

- **Category**: Information Gathering / OSINT / Email & Subdomain Enumeration
- **Risk Level**: 🟢 Low

---

## Description

theHarvester is an OSINT tool focused on collecting email addresses, hostnames, subdomains, IP addresses, open ports, and other information from public data sources. It is particularly suited for the information gathering phase before penetration testing, obtaining intelligence without touching the target system by querying search engines, DNS databases, public APIs, and similar sources.

## Installation

```bash
theHarvester -h

sudo apt install theharvester
git clone https://github.com/laramies/theHarvester
cd theHarvester && pip3 install -r requirements/base.txt

# Configure API keys
# System-wide (Kali default install):
nano /etc/theHarvester/api-keys.yaml
# User-level (pip/git install):
mkdir -p ~/.local/share/theHarvester
nano ~/.local/share/theHarvester/api-keys.yaml
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Company name or domain to search |
| `-l <count>` | Limit the number of search results (default: 500) |
| `-b <source>` | Data source (comma-separated or all) |
| `-f <file>` | Output to JSON and XML files (creates `<file>.json` and `<file>.xml`) Example: `-f results` |
| `-e <DNS server>` | DNS server to use for lookup |
| `--dns-resolve` | Perform DNS resolution on subdomains with a resolver list |
| `-t`, `--take-over` | Check for subdomain takeovers |
| `-c`, `--dns-brute` | Perform DNS brute force on the domain |
| `-a`, `--api-scan` | Scan for API endpoints |
| `--screenshot <dir>` | Take screenshots of resolved domains to specified output directory |
| `--shodan` | Query discovered hosts with Shodan |

## Common Commands

### Basic Search

```bash
# Search using all data sources
theHarvester -d example.com -b all

# Specify data sources
theHarvester -d example.com -b google,bing,baidu

# Limit number of results
theHarvester -d example.com -b google -l 200

# Search with Google and output report
theHarvester -d example.com -b google -l 500 -f example_report
```

### Email Collection

```bash
# Optimized for email collection (use hunter, linkedin, etc.)
theHarvester -d example.com -b hunter,linkedin,google

theHarvester -d example.com -b google --dns-resolve
```

### Subdomain Enumeration

```bash
# Use certificate transparency data sources
theHarvester -d example.com -b crtsh,certspotter,dnsdumpster

# Comprehensive subdomain search
theHarvester -d example.com -b all -l 1000 -f report
```

### Using Shodan

```bash
# Combine Shodan to get port information
theHarvester -d example.com -b shodan --shodan
```

## Notes & Tips

1. **API Keys**: Configuring API keys yields more results, especially for Hunter and VirusTotal
2. **Rate Limiting**: Search engines like Google have CAPTCHAs; frequent use may result in temporary blocks
3. **Result Quality**: Quality varies significantly across data sources; cross-validation with multiple sources is recommended
4. **Combine With**: Use alongside amass and sublist3r to obtain a more complete subdomain list

---

## Official References

- [theHarvester GitHub](https://github.com/laramies/theHarvester)
