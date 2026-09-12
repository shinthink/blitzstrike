# changeme

- **Category**: Password Attacks / Default Credential Scanning
- **Risk Level**: 🟡 Medium

---

## Description

Scans network services for default and known credentials. Uses a built-in database of default credentials for common devices, appliances, and services. Supports HTTP basic/form auth, SSH, SNMP, MSSQL, MySQL, PostgreSQL, MongoDB, FTP, and more. Useful for quickly identifying low-hanging fruit on a network where devices may still use factory defaults.

## Installation

```bash
sudo apt install changeme
# Or install via pip
pip3 install changeme
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `target` | Target IP, CIDR range, or file containing targets |
| `-a`, `--all` | Scan all supported protocols |
| `-c <category>` | Filter by category |
| `--protocols <proto>` | Comma-separated list of protocols to test (default: http) |
| `-n <cred_name>` | Narrow testing to the supplied credential name |
| `--threads <threads>` | Number of threads (default 10) |
| `--timeout <secs>` | Timeout in seconds for a request (default: 10) |
| `-p <url>` | HTTP(S) proxy |
| `-f`, `--fingerprint` | Fingerprint targets but don't check creds |
| `--dryrun` | Print URLs to scan but don't scan them |
| `--ssl` | Force SSL and fall back to non-SSL if error |
| `-o <file>` | Output results file (extension determines format) |
| `--oa` | Output results in csv, html and json formats |
| `-r`, `--resume` | Resume a previous scan |
| `-q <query>` | Shodan search query |
| `-k <key>` | Shodan API key |
| `--dump` | Print all of the loaded credentials |
| `-l <file>` | Write logs to logfile |
| `-dl <ms>` | Delay in milliseconds to avoid 429 status codes (default: 500) |
| `-d`, `--debug` | Debug output |

## Common Commands

```bash
# Scan a subnet for all default credentials
changeme --all 192.168.1.0/24

# Scan specific protocols only
changeme --protocols ssh,ftp 192.168.1.0/24

# Scan a single target for HTTP default credentials
changeme --protocols http 192.168.1.100

# Dump the entire default credential database
changeme --dump

# Scan with proxy (useful with Burp Suite)
changeme --protocols http --proxy http://127.0.0.1:8080 192.168.1.0/24

# Scan with rate limiting to reduce detection risk
changeme --all --threads 2 --delay 3 192.168.1.0/24

# Resume an interrupted scan
changeme --resume

# Scan for a specific named credential set
changeme --name tomcat 192.168.1.0/24

# Scan targets from a file with verbose output
changeme --all --verbose --threads 5 /tmp/targets.txt
```

## Notes & Tips

1. Run changeme early in a penetration test — default credentials are among the easiest wins and are frequently overlooked.
2. Use `--dump` to review all known credentials in the database before scanning, to understand coverage.
3. Pair with `nmap` service detection: scan the network first with `nmap -sV`, then target discovered services with changeme.
4. HTTP form-based authentication may require manual tuning if the login page structure differs from expected patterns.
5. Default credential findings are typically rated Medium severity but can escalate to Critical if the device provides administrative access to infrastructure.

---

## Official References

- [changeme (GitHub)](https://github.com/ztgrace/changeme)
- [Kali changeme](https://www.kali.org/tools/changeme/)
