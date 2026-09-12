# dnsx

- **Category**: Information Gathering / DNS Analysis
- **Risk Level**: 🟢 Low

---

## Description

A fast, multi-purpose DNS toolkit by ProjectDiscovery. Resolves domains in bulk, brute-forces subdomains, and extracts DNS records (A, CNAME, MX, TXT, NS, SOA). Pipeline-friendly — reads from stdin and integrates directly with subfinder, httpx, and other ProjectDiscovery tools. Much faster than `dig` for bulk operations; use it to filter valid subdomains from large discovery lists.

## Installation

```bash
sudo apt install dnsx
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l <file>` | List of sub(domains)/hosts to resolve (file or stdin) |
| `-d <domain>` | List of domains to bruteforce (file or comma-separated or stdin) |
| `-w <wordlist>` | List of words to bruteforce (file or comma-separated or stdin) |
| `-r <file>` | List of resolvers to use (file or comma-separated) |
| `-a` | Query A record (default) |
| `-aaaa` | Query AAAA record |
| `-cname` | Query CNAME record |
| `-mx` | Query MX record |
| `-txt` | Query TXT record |
| `-ns` | Query NS record |
| `-resp` | Display dns response |
| `-resp-only` | Display dns response only |
| `-rc <codes>` | Filter result by dns status code (e.g., noerror,servfail,refused) |
| `-t <n>` | Number of concurrent threads to use (default 100) |
| `-silent` | Output results only |
| `-json` | Write output in JSONL(ines) format |
| `-o <file>` | Output file path |

## Common Commands

```bash
# Resolve a list of subdomains (filter valid ones)
dnsx -l subdomains.txt -a -silent

# Pipe subfinder output directly into dnsx
subfinder -d example.com -silent | dnsx -a -silent

# Subdomain brute-force with wordlist
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -a

# Extract only IP addresses from resolved domains
dnsx -l subdomains.txt -a -resp-only

# Extract MX records (mail server discovery)
dnsx -d example.com -mx -resp

# Extract TXT records (SPF, DMARC, verification tokens)
dnsx -d example.com -txt -resp

# Full recon pipeline: discover → resolve → probe
subfinder -d example.com -silent | dnsx -a -silent | httpx -silent

# Filter only domains that resolve (NOERROR only)
dnsx -l domains.txt -rc NOERROR -a -silent
```

## Notes & Tips

1. dnsx is far faster than `dig` for bulk resolution — use it to filter valid subdomains from large subfinder/amass output lists.
2. `-rc NOERROR` filters for domains that resolve, discarding NXDOMAIN (non-existent) responses cleanly.
3. Use `-resp` to see the actual DNS answer alongside the queried domain — essential for CNAME chain analysis.
4. Configure custom resolvers with `-r resolvers.txt` to avoid rate-limiting by public DNS servers on large jobs.
5. TXT records frequently contain API keys, cloud verification tokens, and internal infrastructure hints — always extract them.

---

## Official References

- [dnsx (GitHub)](https://github.com/projectdiscovery/dnsx)
- [Kali dnsx](https://www.kali.org/tools/dnsx/)
