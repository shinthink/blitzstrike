# Sherlock

- **Category**: Information Gathering / Username OSINT
- **Risk Level**: 🟢 Low

---

## Description

Sherlock searches for usernames across 400+ social media sites, identifying accounts associated with a given username. It is useful during the OSINT phase for building target profiles, discovering online presence, and correlating identities across platforms. Written in Python and maintained by the Sherlock Project.

## Installation

```bash
sudo apt install sherlock

sherlock --help

# Or install via pip
pip3 install sherlock-project

# Or clone and install from source
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip3 install -r requirements.txt
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<username>` | One or more usernames to search (positional); use `{?}` to check similar usernames (replaces to `_`, `-`, `.`) |
| `-o <file>` | Save the output of the result to this file |
| `-fo <folder>` | Save results to this folder when using multiple usernames |
| `--csv` | Create Comma-Separated Values (CSV) file |
| `--json <file>` | Load data from a JSON file or an online valid JSON file |
| `--xlsx` | Create the standard file for Microsoft Excel spreadsheet (xlsx) |
| `--site <sitename>` | Limit analysis to just the listed sites (can be repeated) |
| `--timeout <seconds>` | Time in seconds to wait for response to requests (default: 60) |
| `-p <proxy>` | Make requests over a proxy (e.g., `socks5://127.0.0.1:1080`) |
| `--tor` | Make requests over Tor; requires Tor installed and in system path |
| `--unique-tor` | Make requests over Tor with new circuit after each request |
| `--print-all` | Output sites where the username was not found |
| `--print-found` | Output sites where the username was found |
| `--no-color` | Don't color terminal output |
| `--nsfw` | Include checking of NSFW sites from default list |
| `--browse` | Browse to all results on default browser |
| `--local` | Force the use of the local data.json file |
| `--no-txt` | Disable creation of a txt file |
| `-v` | Display extra debugging information and metrics |

## Common Commands

### Scenario 1: Basic Username Search

```bash
# Search for a single username across all sites
sherlock targetuser

# Search for multiple usernames
sherlock user1 user2 user3
```

### Scenario 2: Output to File

```bash
# Save results to a text file
sherlock targetuser -o results.txt

# Save results in CSV format
sherlock targetuser --csv -o results.csv

# Save results in Excel format
sherlock targetuser --xlsx -o results.xlsx
```

### Scenario 3: Targeted Search

```bash
# Search only on specific sites
sherlock targetuser --site github --site twitter

# Show all results including not-found sites
sherlock targetuser --print-all
```

### Scenario 4: Privacy and Rate Limiting

```bash
# Route through Tor
sherlock targetuser --tor

# Use a proxy
sherlock targetuser -p socks5://127.0.0.1:1080

# Set request timeout
sherlock targetuser --timeout 10
```

### Scenario 5: Pipeline Integration

```bash
# Save CSV output and extract found URLs
sherlock targetuser --csv -o results.csv
awk -F',' '$NF ~ /Claimed/ {print $2}' results.csv

# Search multiple usernames from a file
cat usernames.txt | xargs sherlock --csv -o batch_results.csv
```

## Notes & Tips

1. Sherlock queries 400+ sites — a full scan can take several minutes. Use `--site` to limit scope when you only need specific platforms.
2. Some sites may rate-limit or block requests. Use `--tor` or `-p` to rotate exit IPs if you encounter blocks.
3. False positives can occur when sites return 200 for non-existent profiles. Verify results manually for critical assessments.
4. Use `--timeout` to skip slow-responding sites and speed up scans.
5. Combine with h8mail for email-based OSINT and breach data correlation after identifying target usernames.

---

## Official References

- [Sherlock Project (GitHub)](https://github.com/sherlock-project/sherlock)
- [Kali Sherlock](https://www.kali.org/tools/sherlock/)
