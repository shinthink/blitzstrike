# JoomScan

- **Category**: Web / CMS Scanning
- **Risk Level**: 🟡 Medium

---

## Description

OWASP JoomScan is a Perl-based Joomla vulnerability scanner. It detects Joomla versions, checks core vulnerability exposure, enumerates components, identifies common misconfigurations, finds administrative paths, checks common backup/log/config files, and writes text and HTML reports. Use it when a target is confirmed or strongly suspected to be Joomla; it complements generic CMS detection and template scanners with Joomla-specific checks.

## Installation

```bash
sudo apt update
sudo apt install joomscan
joomscan -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--url, -u <URL>` | Joomla URL or domain to scan |
| `--enumerate-components, -ec` | Try to enumerate installed Joomla components |
| `--cookie <string>` | Send a cookie with requests |
| `--user-agent, -a <user-agent>` | Use the specified User-Agent |
| `--random-agent, -r` | Use a random User-Agent |
| `--timeout <seconds>` | Set request timeout |
| `--proxy <proxy>` | Use an HTTP, HTTPS, or SOCKS proxy |

| `--about` | Show author/about information |
| `--help, -h` | Show help |
| `--version` | Print version and exit |

## Common Commands

```bash
# Basic Joomla scan
joomscan -u https://target.com/

# Enumerate Joomla components
joomscan -u https://target.com/ --enumerate-components

# Authenticated or session-aware scan using a cookie
joomscan -u https://target.com/ --cookie "PHPSESSID=value; other=value"

# Use a custom User-Agent
joomscan -u https://target.com/ -a "Mozilla/5.0"

# Randomize User-Agent and set timeout
joomscan -u https://target.com/ --random-agent --timeout 20

# Route traffic through an intercepting proxy
joomscan -u https://target.com/ --proxy http://127.0.0.1:8080

# Update JoomScan when the installed version supports it
# Update via apt (--update flag not available in v0.0.7)
sudo apt update && sudo apt install --only-upgrade joomscan

# Copy Kali reports to a normalized evidence directory
mkdir -p /tmp/joomscan
cp -a /usr/share/joomscan/reports/* /tmp/joomscan/
```

## Notes & Tips

1. Run JoomScan only after CMS fingerprinting suggests Joomla; use `whatweb`, `cmseek`, or page evidence first.
2. Use `--enumerate-components` for deeper Joomla coverage, but expect more requests.
3. JoomScan reports are commonly written under `/usr/share/joomscan/reports/` on Kali; copy them into the assessment evidence directory.
4. Update via `apt update && apt install --only-upgrade joomscan` (the `--update` flag is not available in the Kali-packaged version).
5. Component findings need manual validation against actual component versions and exposure.
6. JoomScan is Joomla-specific and does not replace WordPress tools such as WPScan or generic scanners such as nuclei.

---

## Official References

- [OWASP JoomScan GitHub](https://github.com/OWASP/joomscan)
- [Kali joomscan](https://www.kali.org/tools/joomscan/)
