# MassDNS

- **Category**: Information Gathering / High-Speed DNS Resolution
- **Risk Level**: 🟢 Low

---

## Description

massdns is a high-performance DNS stub resolver for bulk DNS resolution and validation. It is useful when `altdns`, `dnsgen`, or custom wordlists produce very large candidate lists that would be slow to resolve with standard tools. Use it to validate large subdomain datasets, then pass resolved hosts to `httpx`, `naabu`, or `nuclei`.

## Installation

```bash
sudo apt update
sudo apt install massdns
massdns -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-r <file>` | Text file containing DNS resolvers |
| `-t <type>` | Record type to be resolved (default: A) |
| `-o <format>` | Flags for output formatting |
| `-w <file>` | Write to the specified output file instead of stdout |
| `-s <n>` | Number of concurrent lookups (default: 10000) |
| `--flush` | Flush the output file whenever a response was received |
| `<file>` | Input domain list |

## Common Commands

```bash
# Resolve A records with a resolver list
massdns -r resolvers.txt -t A -o S -w /tmp/massdns.txt candidates.txt

# Extract resolved hostnames
awk '/ A / {print $1}' /tmp/massdns.txt | sed 's/\\.$//' | sort -u > /tmp/resolved.txt

# Resolve dnsgen output
dnsgen subdomains.txt | massdns -r resolvers.txt -t A -o S -w /tmp/generated-resolved.txt

# Chain resolved hosts into httpx
awk '/ A / {print $1}' /tmp/massdns.txt | sed 's/\\.$//' | httpx -silent -title
```

## Notes & Tips

1. Use a reliable resolver list; poor resolvers create false negatives and noisy output.
2. massdns is very fast and can generate high DNS volume; tune scope and rate responsibly.
3. It is best used after candidate generation with `dnsgen`, `altdns`, or custom permutations.
4. Deduplicate and normalize trailing dots before passing output to HTTP or port scanners.

---

## Official References

- [massdns GitHub](https://github.com/blechschmidt/massdns)
- [Kali massdns](https://www.kali.org/tools/massdns/)
