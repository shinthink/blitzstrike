# SpiderFoot

- **Category**: Information Gathering / OSINT
- **Risk Level**: 🟢 Low

---

## Description

A comprehensive OSINT automation framework that queries 200+ data sources to gather intelligence about a target — IP addresses, domains, hostnames, email addresses, ASNs, and person names. Integrates VirusTotal, Shodan, HaveIBeenPwned, Censys, and many other sources in a single scan. Offers both a CLI interface and a web-based GUI with visualization. Used at the start of engagements to rapidly build a complete picture of the target's exposure.

## Installation

```bash
sudo apt install spiderfoot
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-s <target>` | Target for the scan |
| `-t <type>` | Event types to collect, comma-separated (modules selected automatically) |
| `-u <usecase>` | Use case: `all`, `footprint`, `investigate`, `passive` |
| `-m <modules>` | Modules to enable (comma-separated) |
| `-x` | STRICT MODE: only enable modules that can directly consume the target; overrides -t and -m |
| `-l <ip:port>` | IP and port to listen on |
| `-o <format>` | Output format: `tab` (default), `csv`, `json` |
| `-H` | Don't print field headers, just data |
| `-n` | Strip newlines from data |
| `-r` | Include the source data field in tab/csv output |
| `-f` | Filter out event types that weren't requested with -t |
| `-F <types>` | Show only a set of event types, comma-separated |
| `-S <length>` | Maximum data length to display (default: all) |
| `-D <delimiter>` | Delimiter for CSV output (default: `,`) |
| `-d` | Enable debug output |
| `-q` | Disable logging (also hides errors) |
| `-T` | List available event types |
| `-M` | List all available modules |
| `-C <scanID>` | Run correlation rules against a scan ID |
| `-max-threads <n>` | Maximum concurrent threads |

## Common Commands

```bash
# Start the web interface (access at http://127.0.0.1:5001)
spiderfoot -l 127.0.0.1:5001

# Passive scan of a domain (no direct contact with target)
spiderfoot -s example.com -u passive -o json

# Full footprint scan
spiderfoot -s example.com -u footprint

# Investigate a specific IP
spiderfoot -s 192.168.1.10 -u investigate

# Scan an email address for breach data
spiderfoot -s target@example.com -u all

# List available modules
spiderfoot -M
```

## Notes & Tips

1. The web interface (`-l`) is recommended for complex investigations — it provides visualization and correlation of findings.
2. Use `-u passive` to ensure no packets are sent directly to the target during OSINT collection.
3. Configure API keys for VirusTotal, Shodan, HaveIBeenPwned, etc. in the web UI Settings page to unlock full module coverage.
4. The `footprint` use case balances thoroughness and noise; use `all` only when maximum coverage is needed.
5. SpiderFoot stores all scan data in a local SQLite database — results persist between sessions for review.

---

## Official References

- [SpiderFoot (GitHub)](https://github.com/smicallef/spiderfoot)
- [Kali spiderfoot](https://www.kali.org/tools/spiderfoot/)
