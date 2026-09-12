# ffuf

- **Category**: Web / Fuzzing / Directory Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

ffuf (Fuzz Faster U Fool) is a Web fuzzing tool written in Go, known for its extreme speed. Supports directory enumeration, parameter discovery, subdomain enumeration, virtual host enumeration, and other modes. Its main feature is using the `FUZZ` keyword as a placeholder that can be inserted at any position in URLs, Headers, or Body for fuzzing, with powerful filtering capabilities.

**Core Capabilities:**
- Multi-position FUZZ (any position in URL/Header/Body/Cookies)
- Multiple wordlists for simultaneous fuzzing (different FUZZ keywords)
- Flexible filter/match rules (status code, response length, word count, line count, time)
- Supports recursive directory scanning
- JSON format output for pipeline processing

## Installation

```bash
apt install ffuf -y

go install github.com/ffuf/ffuf/v2@latest
```

## Parameter Reference

### Input

| Parameter | Description |
|------|------|
| `-w wordlist` | Wordlist file (`-w file.txt:FUZZ` to specify keyword) |
| `-u URL` | Target URL; use `FUZZ` to mark injection point |
| `-request file` | Read from raw HTTP request file |
| `-request-proto` | Request protocol (http/https; used with -request) |
| `-mode` | Multi-wordlist mode: `clusterbomb` (Cartesian product; default) / `pitchfork` (one-to-one) / `sniper` (one wordlist iterates while others stay fixed) |
| `-ic` | Ignore wordlist comments (lines starting with `#`) |

### HTTP Request

| Parameter | Description |
|------|------|
| `-X method` | HTTP method (GET/POST/PUT/DELETE, etc.) |
| `-d data` | POST data body |
| `-H header` | Extra HTTP headers (can be used multiple times) |
| `-b cookie` | Cookie string |
| `-e extensions` | Comma-separated list of extensions; extends FUZZ keyword |
| `-r` | Follow redirects |
| `-recursion` | Scan recursively; only FUZZ keyword is supported, URL must end in it |
| `-recursion-depth` | Maximum recursion depth (default 0; set an explicit limit for controlled scans) |
| `-replay-proxy` | Replay matching requests to a proxy |
| `-x proxy` | Use HTTP proxy |

### Filtering and Matching

| Parameter | Description |
|------|------|
| `-mc codes` | Match HTTP status codes (default `200-299,301,302,307,401,403,405,500`) |
| `-ms size` | Match response size (bytes) |
| `-mw words` | Match response word count |
| `-ml lines` | Match response line count |
| `-mr regex` | Match response body with regex |
| `-mt time` | Match response time to first byte in milliseconds (e.g., `>100` or `<100`) |
| `-fc codes` | Filter HTTP status codes |
| `-fs size` | Filter response size (bytes; comma-separated for multiple) |
| `-fw words` | Filter response word count |
| `-fl lines` | Filter response line count |
| `-fr regex` | Filter response body with regex |
| `-ft time` | Filter by response time to first byte in milliseconds (e.g., `>100` or `<100`) |

### Performance

| Parameter | Description |
|------|------|
| `-t threads` | Concurrent threads (default 40) |
| `-rate rate` | Maximum requests per second |
| `-timeout seconds` | HTTP timeout (default 10 seconds) |
| `-p delay` | Delay between requests (e.g., `0.1`; supports range `0.1-2.0`) |

### Output

| Parameter | Description |
|------|------|
| `-o file` | Output to file |
| `-of format` | Output format: json/ejson/html/md/csv/ecsv |
| `-v` | Verbose mode (show redirects, etc.) |
| `-s` | Silent mode (results only) |
| `-ac` | Auto-calibration (automatically detect and filter default responses) |
| `-acc` | Custom auto-calibration string (can be used multiple times; implies `-ac`) |
| `-ach` | Per-host auto-calibration |
| `-od dir` | Directory path to store (scrape) matched responses to |
| `-or` | Don't create the output file if there are no results |

## Common Commands

### Scenario 1: Basic Directory Enumeration

```bash
# Simplest usage
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 50 threads, filter 404
ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50 -fc 404
```

### Scenario 2: File Extension Enumeration

```bash
# Use two FUZZ keywords (need to specify different variable names)
ffuf -u http://target.com/FUZZ.EXT \
  -w /usr/share/wordlists/dirb/common.txt:FUZZ \
  -w extensions.txt:EXT \
  -mode clusterbomb

# Common: fixed extensions
ffuf -u "http://target.com/FUZZ" \
  -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.html,.txt,.bak
```

### Scenario 3: Auto-Calibration Filtering (Recommended)

```bash
# -ac automatically detects response patterns and filters false positives
ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -ac

# Filter by response size (run once first to find default size, then filter)
ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -fs 1234    # Filter responses of 1234 bytes
```

### Scenario 4: Parameter Fuzzing

```bash
# GET parameter name enumeration
ffuf -u "http://target.com/page.php?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 1234   # Filter normal page size

# POST parameter enumeration
ffuf -u http://target.com/login.php \
  -X POST \
  -d "FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 1234

# Parameter value fuzzing (known parameter name)
ffuf -u "http://target.com/page.php?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/numbers.txt
```

### Scenario 5: Subdomain Enumeration

```bash
# DNS-based subdomain brute-force: FUZZ the hostname in the URL (DNS must resolve each)
ffuf -u http://FUZZ.target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac
# Note: Do NOT add -H "Host: FUZZ.target.com" here — the Host header is already derived from the URL.
# For virtual host enumeration against a single IP (no DNS), see Scenario 6.
```

### Scenario 6: Virtual Host Enumeration

```bash
ffuf -u http://10.10.10.10 \
  -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 612   # Filter default page size
```

### Scenario 7: POST Data Injection

```bash
# Username enumeration (test which usernames exist)
ffuf -u http://target.com/login.php \
  -X POST \
  -d "username=FUZZ&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -mr "Invalid password"  # Match "password incorrect" message (meaning user exists)

# Password brute-forcing
ffuf -u http://target.com/login.php \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/wordlists/rockyou.txt \
  -mr "Welcome"  # Match successful login indicator
```

### Scenario 8: Recursive Scanning

```bash
ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -recursion \
  -recursion-depth 2 \
  -e .php,.html
```

### Scenario 9: Import from Burp Request File

```bash
# Save Burp request to request.txt, replace target position with FUZZ
ffuf -request request.txt \
  -request-proto http \
  -w /usr/share/wordlists/dirb/common.txt
```

### Scenario 10: JSON Output

```bash
ffuf -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -of json -o results.json

# Process results with jq
cat results.json | jq '.results[] | .url'
```

## Notes & Tips

1. **`-ac` auto-calibration**: Recommended in most cases; automatically excludes false positives, more convenient than manually specifying `-fs`.
2. **Multi-wordlist modes**: `clusterbomb` is Cartesian product (M×N requests; default when `-mode` is not set); `pitchfork` is one-to-one (max(M,N) requests); `sniper` iterates one wordlist at a time while others stay fixed — be mindful of request volume when choosing.
3. **Rate control**: The `-rate` parameter limits requests per second, avoiding overwhelming the target or triggering rate limiting.
4. **Recursive scanning**: `-recursion` can generate large numbers of requests; recommend setting `-recursion-depth 2` to limit depth.
5. **Comparison with gobuster**: ffuf is more flexible and supports fuzzing at any position; gobuster has simpler syntax and is better suited for direct directory enumeration.
6. **Custom API routes**: generic wordlists (SecLists `api-endpoints-res.txt`) miss application-specific paths. For custom APIs, generate a targeted wordlist from documentation or observed traffic: `grep -oE '/v[0-9]+/[a-z_/{}]+' api-docs.md | sort -u > custom_paths.txt`.

---

## Official References

- [ffuf GitHub](https://github.com/ffuf/ffuf)
