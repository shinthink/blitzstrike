# nikto

- **Category**: Web / Web Server Vulnerability Scanning
- **Risk Level**: 🟡 Medium

---

## Description

A vulnerability scanning tool designed specifically for Web servers. Contains 6700+ known vulnerability checks covering outdated software, dangerous files, misconfigurations, HTTP methods, XSS, SQL injection, and more. Scanning has a distinctive fingerprint and is easily detected by WAF and IDS.

## Installation

```bash
sudo apt install nikto
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-h HOST` | Target address |
| `-p PORT` | Port (default 80) |
| `-ssl` | Force SSL |
| `-nossl` | Disable SSL |
| `-id USER:PASS` | HTTP Basic authentication |
| `-Cgidirs all` | Check all CGI directories |
| `-Tuning X` | Test types (1-9,0,a-e,x) |
| `-Plugins PLUGINS` | Specify plugins |
| `-Format FORMAT` | Output format (csv/htm/json/xml/txt/sql) |
| `-o FILE` | Output file |
| `-evasion X` | IDS evasion / encoding technique (1-8, A, B) — commonly used to bypass WAF/IDS (see below) |
| `-mutate X` | Guess additional file names / enumerate (1-4, 6) — e.g. password file names, Apache/cgiwrap usernames |
| `-Display X` | Control output detail (1-4, D, E, P, S, V) — e.g. show redirects, cookies, all 200s, debug, progress |
| `-Pause N` | Seconds to pause between each test (rate-limit / reduce detection) |
| `-useproxy PROXY` | Use proxy |
| `-timeout N` | Timeout in seconds |
| `-maxtime N` | Maximum scan duration (supports s/m/h suffixes) |
| `-useragent <string>` | Custom User-Agent header |
| `-Add-header <header>` | Add custom HTTP header (repeatable, one per flag) |
| `-vhost HOST` | Virtual host header |

### Tuning Types

| Value | Test Type |
|----|---------|
| 1 | Interesting File / Seen in logs |
| 2 | Misconfiguration / Default File |
| 3 | Information Disclosure |
| 4 | Injection (XSS/Script/HTML) |
| 5 | Remote File Retrieval - Inside Web Root |
| 6 | Denial of Service |
| 7 | Remote File Retrieval - Server Wide |
| 8 | Command Execution / Remote Shell |
| 9 | SQL Injection |
| 0 | File Upload |
| a | Authentication Bypass |
| b | Software Identification |
| c | Remote Source Inclusion |
| d | WebService |
| e | Administrative Console |
| x | Reverse Tuning Options (include all except specified) |

### Evasion Techniques (`-evasion`)

| Value | Technique |
|----|---------|
| 1 | Random URI encoding (non-UTF8) |
| 2 | Directory self-reference (/./) |
| 3 | Premature URL ending |
| 4 | Prepend long random string |
| 5 | Fake parameter |
| 6 | TAB as request spacer |
| 7 | Change the case of the URL |
| 8 | Use Windows directory separator (\) |
| A | Use a carriage return (0x0d) as a request spacer |
| B | Use binary value 0x0b as a request spacer |

### Mutate Options (`-mutate`)

| Value | Action |
|----|---------|
| 1 | Test all files with all root directories |
| 2 | Guess for password file names |
| 3 | Enumerate user names via Apache (/~user type requests) |
| 4 | Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests) |
| 6 | Attempt to guess directory names from the supplied dictionary file |

## Common Commands

```bash
# Basic scan
nikto -h http://target.com

# HTTPS target
nikto -h https://target.com -ssl

# Specify port
nikto -h target.com -p 8080

# Comprehensive scan (all types, slower)
nikto -h target.com -Cgidirs all

# Scan for information disclosure and misconfigurations only
nikto -h target.com -Tuning 23

# HTML report
nikto -h target.com -Format htm -o /tmp/nikto_report.html

# JSON report
nikto -h target.com -Format json -o /tmp/nikto_report.json

# Use Burp proxy
nikto -h target.com -useproxy http://127.0.0.1:8080

# Batch scanning
nikto -h targets.txt -Format htm -o /tmp/batch_report.html

# Set User-Agent
nikto -h target.com -useragent "Mozilla/5.0 (compatible)"

# Limit scan duration (5 minutes)
nikto -h target.com -maxtime 5m
```

## Notes & Tips
1. Scanning fingerprint is very distinctive; use with caution in production environments — nikto is not stealthy and will appear in server logs.
2. Recommend using wafw00f to detect WAF first; nikto may generate false positives or miss vulnerabilities when a WAF is present.
3. Older nikto output may contain OSVDB numbers (from a now-defunct vulnerability database); newer versions primarily use CVE identifiers — cross-reference any CVE numbers in NVD for details.
4. Use `-maxtime 5m` to cap scan duration on large sites; without it, full scans can run for hours on complex applications.
5. Combine with sslscan before nikto — knowing the exact TLS configuration helps interpret SSL-related nikto findings correctly.
6. **Proxy incompatibility**: nikto detects and rejects MITM proxy certificates (TLS fingerprinting), aborting the scan early. Do not route nikto through mitmproxy. For authenticated APIs, inject headers directly with `-Add-header "Cookie: token=VALUE"`.

---

## Official References

- [nikto GitHub](https://github.com/sullo/nikto)
