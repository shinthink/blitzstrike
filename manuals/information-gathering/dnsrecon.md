# DNSRecon

- **Category**: Information Gathering / DNS Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

A comprehensive DNS reconnaissance tool supporting multiple modes including standard record enumeration, zone transfers, Bing enumeration, crt.sh enumeration, brute-force, reverse lookups, and cache snooping. Supports rich output formats (JSON/XML/CSV).

## Installation

```bash
sudo apt install dnsrecon
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d DOMAIN` | Target domain |
| `-t TYPE` | Type of enumeration to perform (std/brt/rvl/axfr/bing/yand/crt/snoop/tld/zonewalk/srv) |
| `-D DICT` | Dictionary file of subdomain and hostnames to use for brute force |
| `-n SERVER` | Domain server to use (if none given, the SOA of the target will be used; comma-separated for multiple) |
| `-r RANGE` | IP range for reverse lookup brute force (first-last or range/bitmask) |
| `-iL FILE` | File containing a list of domains to enumerate, one per line |
| `--db FILE` | SQLite 3 file to save found records |
| `-j FILE` | Save output to a JSON file |
| `-x FILE` | XML file to save found records |
| `-c FILE` | Save output to a comma separated value (CSV) file |
| `--threads N` | Number of threads for lookups and brute force |
| `--lifetime N` | Time to wait for a server to respond to a query (default: 3.0) |
| `--tcp` | Use TCP protocol to make queries |
| `-a` | Perform AXFR with standard enumeration |
| `-k` | Perform crt.sh enumeration with standard enumeration |
| `-z` | Perform DNSSEC zone walk with standard enumeration |
| `-f` | Filter out wildcard-resolved records from brute force results |
| `--iw` | Continue brute forcing even if a wildcard record is discovered |
| `-v` | Enable verbose output |

## Common Commands

```bash
# Standard scan (NS, MX, SOA, TXT, SRV, PTR, CNAME, etc.)
dnsrecon -d target.com -t std

# Zone transfer
dnsrecon -d target.com -t axfr

# Subdomain brute-force enumeration
dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Reverse IP range lookup
dnsrecon -r 192.168.1.0/24 -t rvl

# Combined scan with JSON output
dnsrecon -d target.com -a -j /tmp/dnsrecon_output.json

# Specify DNS server
dnsrecon -d target.com -t std -n 8.8.8.8
```

## Notes & Tips

1. Use `std` as the first scan type to quickly enumerate common record types (NS, MX, SOA, TXT, SRV); then add `axfr` to test for zone transfer misconfiguration.
2. Brute-force mode (`-t brt`) can be slow with large wordlists; increase `--threads` (e.g., 50–100) for faster enumeration.
3. Output to JSON (`-j`) or SQLite (`--db`) to preserve results for later analysis or import into reporting tools.
4. `rvl` (reverse lookup) mode is useful for discovering additional hostnames in a target IP range.
5. dnsrecon is more actively maintained than dnsenum and supports more record types; prefer it for thorough DNS reconnaissance.

---

## Official References

- [dnsrecon GitHub](https://github.com/darkoperator/dnsrecon)
