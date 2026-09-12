# h8mail

- **Category**: Information Gathering / Breach Intelligence
- **Risk Level**: 🟢 Low

---

## Description

h8mail is an email OSINT and breach hunting tool. It searches multiple breach databases and public paste sites for email addresses and associated leaked credentials. Supports HaveIBeenPwned, Hunter.io, Snusbase, and local breach databases. Useful for assessing credential exposure during the OSINT phase. Written in Python.

## Installation

```bash
sudo apt install h8mail

h8mail --help

# Or install via pip
pip3 install h8mail

# Generate a sample configuration file
h8mail --gen-config
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-t <target>` | Target email(s), string inputs or files |
| `-q` | Perform a custom query (supports username, password, ip, hash, domain) |
| `-c <file>` | Configuration file path for API keys |
| `-o <file>` | File to write CSV output |
| `-bc <path>` | Path to the breachcompilation torrent folder |
| `-sk` | Skips Scylla and HunterIO check, ideal for local scans |
| `-k <K=V,K=V>` | Pass config options inline as comma-separated key=value pairs (e.g. `"hibp=KEY,emailrep=KEY"`) |
| `-j <file>` | File to write JSON output |
| `-lb <file>` | Local cleartext breaches to scan for targets |
| `-gz <file>` | Gzip-compressed breach files |
| `-sf` | Single-file mode for breach files |
| `-ch [LIMIT]`, `--chase [LIMIT]` | Chase related emails from hunter.io into the target list. Optional `CHASE_LIMIT` sets how many emails per target to chase (needs a hunter.io key unless used with `--power-chase`) |
| `--power-chase` | Aggressively chase related emails from ALL API services (use with `--chase`) |
| `--hide` | Only show the first 4 characters of found passwords (good for demos/screenshots) |
| `--gen-config`, `-g` | Generate a configuration file template (`h8mail_config.ini`) in the current directory and exit (overwrites any existing one) |
| `--debug` | Enable debug output |
| `--loose` | Allow loose search by disabling email pattern recognition |
| `-u <url>` | URL string inputs or files for email parsing |

## Common Commands

### Scenario 1: Basic Email Lookup

```bash
# Search for a single email
h8mail -t target@example.com

# Search for multiple emails
h8mail -t user1@example.com,user2@example.com

# Search emails from a file (one per line)
h8mail -t targets.txt
```

### Scenario 2: Using API Keys

```bash
# Generate a sample config file
h8mail --gen-config

# Search using API keys from config
h8mail -t target@example.com -c h8mail_config.ini
```

### Scenario 3: Local Breach Data

```bash
# Search against a local breach compilation folder
h8mail -t target@example.com -bc /path/to/breach-compilation

# Search a local breach text file
h8mail -t target@example.com -lb breach_dump.txt

# Skip online services — local only
h8mail -t target@example.com -bc /path/to/breach-compilation -sk
```

### Scenario 4: Output and Reporting

```bash
# Save results to a text file
h8mail -t target@example.com -o results.txt

# Save results in JSON format
h8mail -t target@example.com -j results.json

# Combine with config and JSON output
h8mail -t targets.txt -c h8mail_config.ini -j report.json
```

### Scenario 5: Loose Matching

```bash
# Use loose matching to find partial email matches in breach data
h8mail -t target@example.com -lb breach_dump.txt --loose
```

## Notes & Tips

1. Generate a config file with `h8mail --gen-config` and add API keys for HaveIBeenPwned, Hunter.io, Snusbase, or LeakLookup to improve results.
2. HaveIBeenPwned v3 API requires a paid key. Free alternatives like Emailrep.io can supplement results.
3. Local breach compilation search (`-bc`) requires the data to be organized in the standard Breach Compilation folder structure.
4. Use `-sk` to skip online services entirely when working in air-gapped environments with only local breach data.
5. Combine with Sherlock: use Sherlock to discover usernames, then h8mail to check associated email addresses for breach exposure.

---

## Official References

- [h8mail (GitHub)](https://github.com/khast3x/h8mail)
- [Kali h8mail](https://www.kali.org/tools/h8mail/)
