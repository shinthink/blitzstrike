# HostHunter

- **Category**: Information Gathering / Virtual Host Discovery
- **Risk Level**: 🟢 Low

---

## Description

HostHunter discovers virtual hostnames associated with IP addresses using OSINT techniques. It queries SSL/TLS certificates and the HackerTarget API to find hostnames hosted on the same server. Useful for discovering additional web applications and expanding attack surface during reconnaissance. Written in Python.

## Installation

```bash
sudo apt install hosthunter

hosthunter -h

# Or install from source
git clone https://github.com/SpiderLabs/HostHunter.git
cd HostHunter
pip3 install -r requirements.txt
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<target_file>` | File containing target IP addresses (one per line, positional) |
| `-o <file>` | Sets the path of the output file |
| `-f <format>` | Choose between CSV and TXT output file formats |
| `-t <ip>` | Scan a single IP |
| `-g, --grab <ports>` | Choose SSL ports to actively scan for certificates |
| `-v, --verify` | Attempt to resolve discovered hostnames |
| `-V` | Displays the current version |
| `--nessus` | Output in Nessus format |

## Common Commands

### Scenario 1: Basic Virtual Host Discovery

```bash
# Discover virtual hosts for a list of IPs
hosthunter targets.txt

# Save results to a file
hosthunter targets.txt -o results.txt
```

### Scenario 2: Output Formats

```bash
# Output in CSV format
hosthunter targets.txt -o results.csv -f csv

# Output in plain text
hosthunter targets.txt -o results.txt -f txt
```

### Scenario 3: Single Target

```bash
# Hunt a single IP address
hosthunter -t 192.168.1.10 -o results.txt

# Single target with CSV output
hosthunter -t 10.0.0.1 -o results.csv -f csv
```

### Scenario 4: Screen Capture

```bash
# Enable screen capture of discovered hosts
hosthunter targets.txt -sc -o results.csv -f csv
```

### Scenario 5: Pipeline Integration

```bash
# Feed a pre-built target list to HostHunter
hosthunter live_hosts.txt -o vhosts.csv -f csv

# Extract unique hostnames from CSV output
cut -d',' -f2 vhosts.csv | sort -u > unique_hostnames.txt
```

## Notes & Tips

1. Prepare the target file with one IP address per line. HostHunter does not accept CIDR notation — resolve ranges to individual IPs first.
2. Use `-t` to quickly test a single IP without creating a target file.
3. Use `-sc` to capture screenshots of discovered web hosts for visual verification during reporting.
4. HackerTarget API queries may be rate-limited. Results vary depending on API coverage for the target IP range.
5. Combine with Nmap for a full workflow: use Nmap to discover live hosts, then HostHunter to enumerate virtual hosts on each IP.

---

## Official References

- [HostHunter (GitHub)](https://github.com/SpiderLabs/HostHunter)
- [Kali HostHunter](https://www.kali.org/tools/hosthunter/)
