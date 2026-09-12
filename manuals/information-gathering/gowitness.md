# gowitness

- **Category**: Information Gathering / Web Service Screenshots
- **Risk Level**: 🟢 Low

---

## Description

A high-speed web screenshot tool that uses a headless Chrome/Chromium browser to take bulk screenshots of large numbers of URLs and generate a searchable HTML report. Faster than eyewitness; ideal for large-scale web asset documentation and report generation.

## Installation

```bash
sudo apt install gowitness
# Or via Go:
go install github.com/sensepost/gowitness@latest
```

> The version shipped in current Kali is **v3.x**, which uses a `scan`/`report` subcommand structure that differs significantly from v2.x. All examples below are written for **v3** (the installed version); v2 equivalents are shown as commented legacy notes.

## Parameter Reference

### Command Structure (v3)

| Parameter | Description |
|-----------|-------------|
| `scan single -u <url>` | Screenshot a single URL |
| `scan file -f <file>` | Screenshot URLs from a file (use `-f -` for stdin) |
| `scan cidr -c <cidr>` | Screenshot hosts across a CIDR range |
| `scan nmap -f <xml>` | Screenshot web services from an Nmap XML file |
| `scan nessus -f <xml>` | Screenshot from a Nessus XML file |
| `report server` | Start the web UI to browse results |
| `report generate` | Generate a static HTML report |
| `report list` | Print a summary of stored results |
| `report migrate` | Migrate a v2 SQLite DB to v3 |
| `version` | Print the gowitness version |

### Common scan flags (v3)

| Parameter | Description |
|-----------|-------------|
| `-t, --threads <n>` | Concurrent threads (default 6) |
| `-T, --timeout <s>` | Page-load timeout in seconds (default 60) |
| `-s, --screenshot-path <dir>` | Where to store screenshots (default `./screenshots`) |
| `--chrome-proxy <proto://host:port>` | HTTP/SOCKS5 proxy for Chrome |
| `--chrome-path <path>` | Path to a specific Chrome/Chromium binary |
| `--delay <s>` | Seconds to wait after navigation before screenshotting (default 3) |
| `--write-db` | **Save results to SQLite** (required for the report server to show data) |
| `--write-db-uri <uri>` | DB URI (sqlite/mysql/postgres; default `sqlite://gowitness.sqlite3`) |
| `--write-jsonl` / `--write-csv` | Save results as JSON lines / CSV |

> **Critical (v3 behavior change):** by default v3 saves **only screenshots**, no metadata. To use `report server`/`report generate` you MUST add one of the `--write-*` flags (commonly `--write-db`) during the scan, otherwise the report will be empty.

## Common Commands

```bash
# Screenshot a single URL (v3)
gowitness scan single -u http://target.com --write-db
#   v2.x legacy: gowitness single http://target.com

# Bulk URLs from a file (v3) — save metadata to SQLite so the report works
gowitness scan file -f urls.txt --write-db
#   v2.x legacy: gowitness file -f urls.txt

# Bulk URLs from stdin
cat urls.txt | gowitness scan file -f - --write-db

# Custom screenshot output directory
gowitness scan file -f urls.txt -s /tmp/screenshots/ --write-db

# Scan a CIDR range (internal network)
gowitness scan cidr -c 192.168.1.0/24 --write-db
#   v2.x legacy: gowitness scan --cidr 192.168.1.0/24

# Screenshot web services from an Nmap XML file
gowitness scan nmap -f /tmp/nmap_scan.xml --write-db
#   v2.x legacy: gowitness nmap -f /tmp/nmap_scan.xml

# Start the report web UI to browse results (v3)
gowitness report server --host 127.0.0.1 --port 7171 --db-uri sqlite://gowitness.sqlite3
#   v2.x legacy: gowitness report serve --address 127.0.0.1:7171
# Access http://127.0.0.1:7171

# Generate a static HTML report instead of running a server
gowitness report generate --db-uri sqlite://gowitness.sqlite3

# Concurrency (default 6 threads in v3)
gowitness scan file -f urls.txt --threads 20 --write-db

# Page-load timeout (v3 uses -T/--timeout, in seconds)
gowitness scan file -f urls.txt -T 15 --write-db

# Use a proxy (v3 uses --chrome-proxy; v2 used --proxy)
gowitness scan file -f urls.txt --chrome-proxy http://127.0.0.1:8080 --write-db
```

## Notes & Tips

1. gowitness v3 reorganized all subcommands — `scan single`, `scan file`, `scan cidr`, `scan nmap` are the v3 equivalents of v2's top-level commands. Browsing/reporting moved under `report server`/`report generate`.
2. The generated report (via `report server`) supports filtering by HTTP status code, title, and technology — ideal for triaging large asset lists.
3. Use `--threads 20` or higher for faster bulk scanning; the v3 default is only 6 threads.
4. Combine with nmap XML output (`gowitness scan nmap -f scan.xml --write-db`) to automatically screenshot all web services discovered during port scanning.
5. **v3 saves no metadata by default** — always add `--write-db` (or `--write-jsonl`/`--write-csv`) during the scan, then point `report server --db-uri` at the same SQLite file. Without `--write-db`, only PNG screenshots are produced and the report UI will be empty.
6. Migrating from v2? Use `gowitness report migrate` to upgrade an existing v2 SQLite database to the v3 schema.

---

## Official References

- [gowitness (GitHub)](https://github.com/sensepost/gowitness)
