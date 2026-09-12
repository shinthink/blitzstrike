# Gobuster

- **Category**: Web / Directory and File Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

gobuster is a high-performance directory/file brute-force enumeration tool written in Go. It also supports DNS subdomain enumeration, virtual host enumeration, S3/GCS bucket enumeration, TFTP file enumeration, and general fuzzing. Compared to dirb/dirbuster, gobuster uses a concurrent design for faster speed and lower resource consumption.

**Core Capabilities:**
- `dir` mode: Directory and file enumeration
- `dns` mode: DNS subdomain enumeration
- `vhost` mode: Virtual host enumeration
- `s3` mode: AWS S3 bucket enumeration
- `gcs` mode: Google Cloud Storage bucket enumeration
- `fuzz` mode: General fuzzing
- `tftp` mode: TFTP file enumeration

## Installation

```bash
apt install gobuster -y

# Manual install (Go environment)
go install github.com/OJ/gobuster/v3@latest
```

## Parameter Reference

### Global Options

| Parameter | Description |
|------|------|
| `--help, -h` | Show help |
| `--version, -v` | Print the version |

### Subcommands

| Subcommand | Description |
|------|------|
| `dir` | Directory/file enumeration mode |
| `dns` | DNS subdomain enumeration mode |
| `vhost` | Virtual host enumeration mode |
| `fuzz` | Fuzzing mode (replaces FUZZ keyword in URL/headers/body) |
| `s3` | AWS S3 bucket enumeration mode |
| `gcs` | Google Cloud Storage bucket enumeration mode |
| `tftp` | TFTP file enumeration mode |

### Shared Subcommand Options

These options are available across most subcommands:

| Parameter | Description |
|------|------|
| `-w, --wordlist` | Path to the wordlist (use `-` for STDIN) |
| `-t, --threads` | Number of concurrent threads (default 10) |
| `-o, --output` | Output file to write results to |
| `-d, --delay` | Time each thread waits between requests (e.g., 1500ms) |
| `-q, --quiet` | Don't print the banner and other noise |
| `--no-progress, --np` | Don't display progress |
| `--no-error, --ne` | Don't display errors |
| `--no-color, --nc` | Disable color output |
| `--debug` | Enable debug output |
| `-p, --pattern` | File containing replacement patterns |
| `--wordlist-offset, --wo` | Resume from a given position in the wordlist |

### dir Mode (Directory Enumeration)

| Parameter | Description |
|------|------|
| `-u, --url` | Target URL (required) |
| `-x, --extensions` | File extension(s) to search for (comma-separated) |
| `-X, --extensions-file` | Read file extensions from a file |
| `-s, --status-codes` | Positive status codes (overridden by blacklist if set) |
| `-b, --status-codes-blacklist` | Negative status codes (default: "404") |
| `--exclude-length, --xl` | Exclude responses by content length (supports ranges) |
| `-c, --cookies` | Cookies to use for requests |
| `-H, --headers` | Extra HTTP headers (repeatable) |
| `-U, --username` | HTTP Basic Auth username |
| `-P, --password` | HTTP Basic Auth password |
| `-a, --useragent` | Custom User-Agent string |
| `--random-agent, --rua` | Use a random User-Agent string |
| `--proxy` | Proxy to use [http(s)://host:port] or [socks5://host:port] |
| `--timeout, --to` | HTTP timeout (default 10s) |
| `-k, --no-tls-validation` | Skip TLS certificate verification |
| `-e, --expanded` | Expanded mode, print full URLs |
| `-f, --add-slash` | Append `/` to each request |
| `-r, --follow-redirect` | Follow redirects |
| `-n, --no-status` | Don't print status codes |
| `--hide-length, --hl` | Hide the length of the body in output |
| `--discover-backup, --db` | Search for backup files upon finding a file |
| `--retry` | Retry on request timeout |
| `--retry-attempts, --ra` | Times to retry on timeout (default 3) |
| `-m, --method` | HTTP method (default "GET") |

### dns Mode (Subdomain Enumeration)

| Parameter | Description |
|------|------|
| `--domain, --do` | Target domain (required) |
| `--resolver` | Custom DNS server (format: server.com or server.com:port) |
| `--protocol` | DNS protocol: 'udp' or 'tcp' (default "udp") |
| `-c, --check-cname` | Also check CNAME records |
| `--timeout, --to` | DNS resolver timeout (default 1s) |
| `--wildcard, --wc` | Force continued operation when wildcard found |
| `--no-fqdn, --nf` | Do not automatically add trailing dot to domain |

### vhost Mode (Virtual Host Enumeration)

| Parameter | Description |
|------|------|
| `-u, --url` | Target URL (required) |
| `--append-domain` | Append domain name after each word |
| `--exclude-length, --xl` | Exclude responses by content length |
| `--domain` | Domain to append (used with --append-domain) |
| Same HTTP options as `dir` mode | (cookies, headers, proxy, TLS, auth, etc.) |

## Common Commands

### Scenario 1: Basic Directory Enumeration

```bash
# Scan using common.txt wordlist
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Multi-thread acceleration (50 threads)
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50

# Show full URLs
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -e
```

### Scenario 2: File Extension Enumeration

```bash
# Enumerate PHP and HTML files
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,bak,zip

# Enumerate backup files
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x bak,old,backup,zip,tar.gz,sql
```

### Scenario 3: Authenticated Scanning

```bash
# Cookie authentication
gobuster dir -u http://target.com/admin \
  -w /usr/share/wordlists/dirb/common.txt \
  -c "session=abc123; token=xyz789"

# HTTP basic authentication
gobuster dir -u http://target.com/admin \
  -w /usr/share/wordlists/dirb/common.txt \
  -U admin -P password123

# Custom header (Bearer Token)
gobuster dir -u http://target.com/api \
  -w /usr/share/wordlists/dirb/common.txt \
  -H "Authorization: Bearer eyJhbGci..."
```

### Scenario 4: Filter by Status Code

```bash
# Show only 200 responses
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -s 200

# Exclude 403 and 404 (blacklist; overrides --status-codes if set)
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -b 403,404
```

### Scenario 5: DNS Subdomain Enumeration

```bash
# Basic subdomain enumeration
gobuster dns -do example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Subdomain enumeration with increased threads
gobuster dns -do example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50

# Use custom DNS server
gobuster dns -do example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --resolver 8.8.8.8
```

### Scenario 6: Virtual Host Enumeration

```bash
gobuster vhost -u http://10.10.10.10 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain

# Exclude specific response lengths (filter default pages)
gobuster vhost -u http://10.10.10.10 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --exclude-length 612
```

### Scenario 7: Through Burp Suite Proxy

```bash
gobuster dir -u https://target.com \
  -w /usr/share/wordlists/dirb/common.txt \
  --proxy http://127.0.0.1:8080 \
  --no-tls-validation
```

### Scenario 8: Output to File

```bash
gobuster dir -u http://target.com \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html -t 40 \
  -o gobuster_results.txt
```

## Notes & Tips

1. **Recommended wordlists**: `common.txt` (`/usr/share/wordlists/dirb/common.txt`) for quick scans, `big.txt` (`/usr/share/wordlists/dirb/big.txt`) for comprehensive scans, `directory-list-2.3-medium.txt` (`/usr/share/wordlists/dirbuster/`) for medium intensity, `directory-list-2.3-big.txt` for large wordlists, `raft-large-directories.txt` (SecLists `Discovery/Web-Content`) as a recommended general choice, and `subdomains-top1million.txt` (SecLists `Discovery/DNS`) for subdomain enumeration. Install SecLists with `apt install seclists -y` (wordlists located at `/usr/share/seclists/`).
2. **Thread count**: Adjust based on server capacity; too high may trigger rate limiting or IP banning. Recommend 20-50.
3. **Wildcard responses**: If the target returns 200 for all requests, use `-b/--status-codes-blacklist` (negative status codes) or `--exclude-length` to filter.
4. **HTTPS certificates**: Add `--no-tls-validation` when testing sites with self-signed certificates.
5. **Rate limiting**: Use `--delay` parameter to reduce request frequency (e.g., `--delay 200ms`).
6. **Large wordlist efficiency**: The medium wordlist has ~220,000 entries; at 50 threads it takes several minutes. Large wordlists take proportionally longer.

---

## Official References

- [gobuster GitHub](https://github.com/OJ/gobuster)
