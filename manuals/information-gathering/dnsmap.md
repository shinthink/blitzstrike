# dnsmap

- **Category**: Information Gathering / DNS Enumeration
- **Risk Level**: 🟢 Low

---

## Description

A DNS subdomain brute-force tool that scans a domain for common subdomains using a built-in wordlist or a custom external one. Produces output in plain text and CSV formats. Includes dnsmap-bulk for scanning multiple domains at once. A simpler and faster alternative to dnsenum for subdomain brute-forcing specifically.

## Installation

```bash
sudo apt install dnsmap
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<domain>` | Target domain to scan |
| `-w <wordlist>` | Custom wordlist file |
| `-r <file>` | Save results to plain text file |
| `-c <file>` | Save results to CSV file |
| `-d <n>` | Delay between requests in milliseconds |
| `-i <ips>` | Comma-separated IPs to ignore (e.g., wildcard DNS responses) |

## Common Commands

```bash
# Basic subdomain brute-force using built-in wordlist
dnsmap example.com

# Use custom wordlist
dnsmap example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Save results to CSV
dnsmap example.com -c results.csv

# Ignore wildcard IP (helps filter false positives)
dnsmap example.com -i 1.2.3.4

# Bulk scan multiple domains
dnsmap-bulk domains.txt /tmp/results/
```

## Notes & Tips

1. Before running, check for wildcard DNS with `dig any.example.com` — if all subdomains resolve to one IP, use `-i` to ignore it.
2. Use `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` as a starting wordlist; the built-in list is smaller.
3. dnsmap does not require root privileges — safe to run in restricted environments.
4. For comprehensive subdomain discovery, combine: dnsmap (brute-force) + subfinder + dnsx (resolution filtering).
5. CSV output (`-c`) integrates well with spreadsheet tools for client reporting.

---

## Official References

- [dnsmap (GitHub)](https://github.com/resurrecting-open-source-projects/dnsmap)
- [Kali dnsmap](https://www.kali.org/tools/dnsmap/)
