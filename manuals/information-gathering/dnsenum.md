# dnsenum

- **Category**: Information Gathering / DNS Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

An automated DNS enumeration tool that integrates DNS record queries, zone transfer attempts, subdomain brute-force enumeration, and reverse lookups. A versatile all-in-one tool for DNS reconnaissance.

## Installation

```bash
sudo apt install dnsenum
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--enum` | Shortcut option equivalent to --threads 5 -s 15 -w |
| `--dnsserver SERVER` | Use specified DNS server |
| `-f` / `--file FILE` | Read subdomains from this file to perform brute force |
| `--subfile FILE` | Write all valid subdomains to this file |
| `--threads N` | Number of threads that will perform different queries |
| `-t, --timeout N` | TCP and UDP timeout values in seconds (default: 10s) |
| `--noreverse` | Skip the reverse lookup operations |
| `--nocolor` | Disable ANSIColor output |
| `-o FILE` | Output in XML format (can be imported in MagicTree) |
| `-p <n>` | Number of Google search pages to process (default: 5) |
| `-s <n>` | Maximum subdomains scraped from Google (default: 15) |

## Common Commands

```bash
# Basic enumeration
dnsenum target.com

# Brute-force subdomains using wordlist
dnsenum --enum target.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Specify DNS server
dnsenum --dnsserver 8.8.8.8 target.com

# Multi-threaded acceleration
dnsenum target.com -f wordlist.txt --threads 20

# Output XML report
dnsenum target.com -o /tmp/dnsenum_result.xml

# Skip reverse lookups (speed up)
dnsenum target.com --noreverse
```

## Notes & Tips
1. Brute-forcing with large wordlists takes significant time; use `--threads` to speed up
2. Prefer passive tools (amass -passive) first, then consider active enumeration

---

## Official References

- [dnsenum GitHub](https://github.com/fwaeytens/dnsenum)
- [Kali dnsenum](https://www.kali.org/tools/dnsenum/)
