# DNSGen

- **Category**: Information Gathering / DNS Permutation
- **Risk Level**: 🟢 Low

---

## Description

dnsgen generates domain and subdomain permutations from an existing list using common DNS naming patterns. It is useful for expanding a validated subdomain set into likely dev, staging, regional, or service-specific names. Use it as a generator, then validate candidates with `dnsx` or `massdns`.

## Installation

```bash
sudo apt update
sudo apt install dnsgen
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<file>` | Input domain/subdomain list |
| `-w <file>` | Custom wordlist |
| `-l <n>` / `--wordlen <n>` | Minimum length of custom words (default 6) |
| `-f` / `--fast` | Faster generation with reduced permutations |

## Common Commands

```bash
# Generate permutations from known subdomains
dnsgen subdomains.txt > dnsgen-candidates.txt

# Use a custom wordlist
dnsgen subdomains.txt -w words.txt > dnsgen-custom.txt

# Generate and resolve with dnsx
dnsgen subdomains.txt | dnsx -a -resp -o /tmp/dnsgen-resolved.txt

# Combine subfinder, dnsgen, and dnsx
subfinder -d example.com -silent | tee subdomains.txt
dnsgen subdomains.txt | dnsx -silent -a -o /tmp/generated-live.txt
```

## Notes & Tips

1. dnsgen is a generator, not a resolver; pipe its output to `dnsx` or `massdns`.
2. Start from validated subdomains to keep the generated list relevant.
3. Custom wordlists improve results when they include product, environment, and region names.
4. Deduplicate output before large-scale resolution.

---

## Official References

- [dnsgen GitHub](https://github.com/AlephNullSK/dnsgen)
- [Kali dnsgen](https://www.kali.org/tools/dnsgen/)
