# dnstwist

- **Category**: Information Gathering / DNS Analysis
- **Risk Level**: 🟢 Low

---

## Description

Generates permutations of a target domain name — typosquatting, homoglyphs, bitsquatting, addition, omission, and more — then checks which permutations are registered. Used to identify phishing infrastructure targeting a brand, detect domain squatting, and find attacker-controlled domains. Also detects cloned websites by fuzzy-hashing page content.

## Installation

```bash
sudo apt install dnstwist
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<domain>` | Target domain to permutate |
| `-r` / `--registered` | Only show registered/resolvable domains |
| `-u` / `--unregistered` | Only show unregistered domain names |
| `-o <file>` | Output results to file |
| `-f <format>` | Output format: `cli` (default), `csv`, `json`, `list` |
| `-d <file>` / `--dictionary` | Generate more domain permutations using dictionary file |
| `--nameservers <servers>` | DNS or DoH servers to query (comma-separated) |
| `-m` / `--mxcheck` | Check if MX host can be used to intercept emails |
| `-g` / `--geoip` | Lookup for GeoIP location |
| `-b` / `--banners` | Grab HTTP and SMTP service banners from live servers |
| `-w` / `--whois` | Lookup WHOIS database for creation date and registrar |
| `-a` / `--all` | Print all DNS records instead of the first ones |
| `--lsh [type]` | Evaluate web page similarity with LSH algorithm (ssdeep, tlsh; default: ssdeep) |
| `-p` / `--phash` | Render web pages and evaluate visual similarity |
| `--screenshots <dir>` | Save web page screenshots into directory |
| `--fuzzers <list>` | Use only selected fuzzing algorithms (comma-separated) |
| `--tld <file>` | Swap TLD for the original domain from file |
| `--useragent <string>` | Set custom User-Agent string |
| `-t <n>` | Start specified number of threads (default: 8) |

## Common Commands

```bash
# Generate all permutations and check registration
dnstwist example.com

# Show only registered permutations (reduces noise)
dnstwist -r example.com

# JSON output for scripting
dnstwist -f json -r example.com

# Save registered domains to CSV
dnstwist -f csv -r example.com -o results.csv

# Full analysis with HTTP banners and GeoIP
dnstwist -r --banners --geoip example.com

# Detect cloned phishing sites with fuzzy hashing
dnstwist -r --lsh ssdeep example.com
```

## Notes & Tips

1. Run dnstwist against the target's domain during OSINT — registered typosquatting domains often indicate active phishing campaigns targeting the organization.
2. `-r` (registered only) eliminates unregistered permutations — reduces output from thousands to the relevant few.
3. `--lsh ssdeep` fuzzy-hashes the target's main page and compares against each permutation — detects cloned phishing sites even if the URL differs.
4. `--banners` shows web server headers on registered permutations — useful for identifying active phishing infrastructure.
5. Findings from dnstwist typically appear in threat intelligence or brand-protection sections of pentest reports.

---

## Official References

- [dnstwist (GitHub)](https://github.com/elceef/dnstwist)
- [Kali dnstwist](https://www.kali.org/tools/dnstwist/)
