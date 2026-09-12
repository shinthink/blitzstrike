# Sublist3r

- **Category**: Information Gathering / Subdomain Enumeration
- **Risk Level**: 🟢 Low

---

## Description

Passively collects subdomains using multiple search engines (Google, Bing, Yahoo, Baidu, Ask, Netcraft, DNSdumpster, VirusTotal, SSL certificates). Fast, suitable for quickly building an initial subdomain list.

> ⚠️ **Note**: ThreatCrowd was previously supported but is now defunct (shut down). Sublist3r versions in current Kali may omit it or skip it silently.

## Installation

```bash
sudo apt install sublist3r
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d DOMAIN` | Domain name to enumerate subdomains for |
| `-b` | Enable the subbrute bruteforce module |
| `-t N` | Number of threads for subbrute bruteforce |
| `-e ENGINES` | Specify search engines (comma-separated) |
| `-o FILE` | Save the results to text file |
| `-v` | Enable verbosity and display results in realtime |
| `-p PORT` | Scan found subdomains against specified TCP ports |

## Common Commands

```bash
# Basic enumeration
sublist3r -d target.com

# Specify search engines
sublist3r -d target.com -e google,bing,virustotal

# Enable brute-force enumeration (uses built-in names.txt wordlist; no -w flag to specify custom wordlist)
sublist3r -d target.com -b

# Save results and scan ports
sublist3r -d target.com -o /tmp/subdomains.txt -p 80,443,8080

# Real-time display
sublist3r -d target.com -v
```

## Notes & Tips

1. sublist3r is primarily passive — it queries search engines and public APIs without sending packets to the target domain.
2. Combine with subfinder for broader coverage — both tools query different data sources.
3. `-t` controls subbrute bruteforce threads (only active when `-b` is used); it does not affect search engine query rate.
4. The `-b` brute-force mode uses a built-in wordlist — for better results use dnsx with SecLists wordlists.
5. sublist3r results may contain duplicates — pipe through `sort -u` when combining with other tools.

---

## Official References

- [Sublist3r GitHub](https://github.com/aboul3la/Sublist3r)
