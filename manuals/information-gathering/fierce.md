# Fierce

- **Category**: Information Gathering / DNS Brute-Force Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

A DNS reconnaissance tool focused on discovering non-contiguous IP blocks and subdomains of a target domain. First attempts zone transfer; if that fails, performs brute-force enumeration and reverse lookups on discovered IPs. Suitable for discovering internal IP ranges.

## Installation

```bash
sudo apt install fierce
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--domain DOMAIN` | Domain name to test |
| `--subdomain-file FILE` | Use subdomains specified in this file (one per line) |
| `--dns-servers DNS` | Use these dns servers for reverse lookups |
| `--dns-file FILE` | Use dns servers specified in this file for reverse lookups (one per line) |
| `--subdomains LIST` | Use these subdomains |
| `--delay SECONDS` | Time to wait between lookups |
| `--wide` | Scan entire class C of discovered records |
| `--traverse N` | Scan N IPs before and after discovered records |
| `--search TERM` | Filter on these domains when expanding lookup |
| `--range RANGE` | Scan an internal IP range |
| `--connect` | Attempt HTTP connection to discovered (non-RFC 1918) hosts |
| `--tcp` | Use TCP instead of UDP for DNS queries |

## Common Commands

```bash
# Basic scan
fierce --domain target.com

# Custom wordlist (use --subdomain-file, not --wordlist)
fierce --domain target.com --subdomain-file /usr/share/wordlists/dirb/small.txt

# Specify DNS server (use space to separate multiple servers)
fierce --domain target.com --dns-servers 8.8.8.8
fierce --domain target.com --dns-servers 8.8.8.8 1.1.1.1

# Add delay between requests (reduce detection)
fierce --domain target.com --delay 1

# Manually test specific subdomains
fierce --domain target.com --subdomains www mail ftp admin

# Widen reverse lookup traversal
fierce --domain target.com --traverse 10

# Output to file
fierce --domain target.com > /tmp/fierce_output.txt
```

## Notes & Tips

1. fierce attempts zone transfer before brute-forcing; the zone transfer result alone can expose all subdomains if the DNS server is misconfigured.
2. The correct flag for a custom wordlist is `--subdomain-file` — there is no `--wordlist` flag (a common mistake).
3. `--wide` and `--traverse` expand the reverse-lookup range around discovered IPs, which often uncovers additional related hosts in the same IP block.
4. Use `--delay` on production targets to avoid triggering rate-limiting or IDS alerts.
5. fierce is best at discovering non-contiguous IP space and internal ranges — complement with subfinder or amass for broader passive subdomain coverage.

---

## Official References

- [fierce GitHub](https://github.com/mschwager/fierce)
