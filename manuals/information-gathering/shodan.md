# shodan (CLI)

- **Category**: Information Gathering / Network Asset Intelligence
- **Risk Level**: 🟢 Low

---

## Description

Shodan is the largest device search engine on the internet, indexing globally exposed device information (ports, services, banners, certificates, vulnerabilities, etc.). The CLI tool allows direct querying of the Shodan database from the command line without sending any traffic to the target. Requires an API Key.

## Installation

```bash
pip install shodan

# Initialize (requires Shodan API Key)
shodan init YOUR_API_KEY
```

## Parameter Reference

### CLI Main Subcommands

| Parameter | Description |
|-----------|-------------|
| `shodan init KEY` | Initialize API Key |
| `shodan search QUERY` | Search for devices |
| `shodan host IP` | Query detailed information for a specific IP |
| `shodan count QUERY` | Count number of matches |
| `shodan download FILE QUERY` | Download search results |
| `shodan parse FILE` | Parse a downloaded results file |
| `shodan info` | Query account quota information |
| `shodan domain DOMAIN` | View all available information for a domain |
| `shodan myip` | Print your external IP address |
| `shodan stats QUERY` | Provide summary information about a search query |
| `shodan scan IP/NETBLOCK` | Scan an IP/netblock using Shodan |
| `shodan honeyscore IP` | Check whether the IP is a honeypot |
| `shodan alert create` | Create real-time monitoring alert |
| `shodan alert list` | List all alerts |

### Common Search Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `hostname:` | Filter by hostname | `hostname:target.com` |
| `org:` | Filter by organization | `org:"Target Corp"` |
| `port:` | Filter by port | `port:3389` |
| `country:` | Filter by country | `country:CN` |
| `ssl.cert.subject.cn:` | Filter by SSL certificate | `ssl.cert.subject.cn:*.target.com` |
| `vuln:` | Filter by CVE | `vuln:CVE-2021-44228` |
| `product:` | Filter by product | `product:"Apache httpd"` |

## Common Commands

```bash
# Search for target-related assets
shodan search "hostname:target.com"
shodan search "org:Target Corporation"
shodan search "ssl.cert.subject.cn:target.com"

# Query details for a specific IP
shodan host 203.0.113.1   # replace with actual target IP

# Download search results
shodan download /tmp/results "hostname:target.com"

# Parse downloaded results
shodan parse /tmp/results.json.gz

# Query your account information
shodan info

# Statistical data
shodan count "apache"

# Search for specific vulnerability (CVE)
shodan search "vuln:CVE-2021-44228"

# Search specific port
shodan search "port:6379 country:CN"  # Redis

# Real-time monitoring
shodan alert create "target" 203.0.113.0/24   # replace with actual target CIDR
shodan alert list
```

### Useful Search Syntax

```bash
# Find IPs for all subdomains of target
shodan search "ssl.cert.subject.cn:*.target.com" --fields ip_str,port

# Find cameras with default passwords
shodan search "default password" --limit 10

# Find open RDP on target
shodan search "org:TargetCorp port:3389"
```

## Notes & Tips

1. A free Shodan API key allows limited queries; a paid membership unlocks more results, filters, and real-time alerts — essential for thorough asset reconnaissance.
2. Use `ssl.cert.subject.cn:*.target.com` to find all hosts presenting TLS certificates for the target domain — often reveals shadow IT and forgotten subdomains.
3. `shodan download` saves results as gzipped JSON for offline analysis; combine with `shodan parse` to extract specific fields.
4. Shodan queries are completely passive — no traffic reaches the target, making it safe for early OSINT before authorization is confirmed.
5. The `vuln:` filter (requires membership) identifies hosts with known CVEs — combine with `org:` to quickly prioritize vulnerable assets in scope.

---

## Official References

- [Shodan CLI](https://help.shodan.io/command-line-interface/0-installation)
- [Shodan Developer API](https://developer.shodan.io/api)
