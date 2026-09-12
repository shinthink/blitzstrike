# DMitry

- **Category**: Information Gathering / Comprehensive OSINT
- **Risk Level**: 🟢 Low

---

## Description

An all-in-one information gathering tool that integrates WHOIS queries, Netcraft information, subdomain search, email address collection, and TCP port scanning in a single run. Suitable for quick initial reconnaissance, though each module lacks the depth of specialized tools.

## Installation

```bash
sudo apt install dmitry
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-w` | Perform a whois lookup on the domain name of a host |
| `-i` | Perform WHOIS query on the resolved IP address of the domain |
| `-n` | Retrieve Netcraft.com information |
| `-s` | Search for subdomains |
| `-e` | Search for email addresses |
| `-p` | TCP port scan |
| `-f` | Perform TCP port scan showing filtered ports (requires `-p`) |
| `-b` | Read banners from scanned ports (requires `-p`) |
| `-t TTL` | TTL in seconds for TCP port scan (default 2) |
| `-o FILE` | Save output to file (without extension; .txt is appended) |

## Common Commands

```bash
# Comprehensive collection (common combination)
dmitry -winsepfb target.com

# WHOIS + subdomain + email only
dmitry -wse target.com

# With port scanning
dmitry -wnsep target.com

# Output to file
# Note: dmitry -o appends .txt automatically; do NOT include .txt in the argument
dmitry -winsepfb target.com -o /tmp/dmitry_result
# Result saved to: /tmp/dmitry_result.txt
```

## Notes & Tips

1. The `-winsepfb` flag combination is the most common "full" run; flags are order-independent but must be combined without spaces.
2. The `-s` subdomain search queries public search engines and is relatively shallow — supplement with amass or subfinder for deeper discovery.
3. The port scanner (`-p`) is slow and basic; prefer nmap for accurate, fast port enumeration.
4. Use `-o` without a `.txt` extension; DMitry automatically appends `.txt` to the filename.
5. Netcraft information (`-n`) may return limited results if the target has low Netcraft coverage; errors here are normal.

---

## Official References

- [DMitry GitHub](https://github.com/jaygreig86/dmitry)
