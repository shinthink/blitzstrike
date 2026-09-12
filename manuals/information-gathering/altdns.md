# Altdns

- **Category**: Information Gathering / DNS Permutation
- **Risk Level**: 🟢 Low

---

## Description

altdns generates likely subdomain permutations from known subdomains and a wordlist, then optionally resolves them. It is useful after initial discovery with `subfinder` or `amass` to find environment-specific names such as `dev-api`, `staging-admin`, or `vpn-east`. Use it with a resolver such as `dnsx` or `massdns` for large-scale validation.

## Installation

```bash
sudo apt update
sudo apt install altdns
altdns -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <file>` | Input subdomain list |
| `-w <file>` | List of words to alter the subdomains with |
| `-o <file>` | Output location for altered subdomains |
| `-r` | Resolve all altered subdomains |
| `-n` | Add number suffix (0-9) to every domain |
| `-e` | Ignore existing domains in file |
| `-s <file>` | Save resolved altered subdomains to file |
| `-t <n>` | Amount of threads to run simultaneously |
| `-d <ip>` | DNS resolver IP address (overrides system default) |

## Common Commands

```bash
# Generate permutations from discovered subdomains
altdns -i subdomains.txt -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o altdns.txt

# Generate and resolve results
altdns -i subdomains.txt -w words.txt -o altdns.txt -r -s altdns-resolved.txt

# Validate generated names with dnsx
altdns -i subdomains.txt -w words.txt -o altdns.txt
dnsx -l altdns.txt -a -resp -o /tmp/altdns-dnsx.txt
```

## Notes & Tips

1. altdns works best after you already have a seed list of real subdomains.
2. Use organization-specific words such as `dev`, `stage`, `vpn`, `admin`, region names, and product names.
3. For very large lists, generate permutations with altdns and resolve with `dnsx` or `massdns`.
4. Avoid uncontrolled permutation size; large wordlists can produce millions of candidates.

---

## Official References

- [altdns GitHub](https://github.com/infosec-au/altdns)
- [Kali altdns](https://www.kali.org/tools/altdns/)
