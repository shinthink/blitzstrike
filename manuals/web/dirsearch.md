# dirsearch

- **Category**: Web / Directory Enumeration
- **Risk Level**: 🟢 Low

---

## Description

A fast web path scanner that brute-forces directories and files on web servers using a built-in wordlist or custom wordlists. Supports multi-extension chaining, recursive scanning, response filtering, and multiple output formats (JSON, XML, CSV, HTML). Frequently used alongside feroxbuster and gobuster — dirsearch's rich built-in wordlist and extension support make it a useful cross-check tool.

## Installation

```bash
sudo apt install dirsearch
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Target URL |
| `-e <ext>` | Extension list separated by commas (e.g. php,asp) |
| `-w <file>` | Customize wordlists (separated by commas) |
| `-t <n>` | Number of threads (default: 25) |
| `-r` | Brute-force recursively |
| `-R <depth>`, `--max-recursion-depth` | Maximum recursion depth (used with `-r`) |
| `--deep-recursive` | Recurse on every directory depth (e.g., `api/users` -> `api/`) |
| `--force-recursive` | Recurse for every found path, not only directories |
| `-i <codes>` | Include status codes, separated by commas, supports ranges |
| `-x <codes>` | Exclude status codes, separated by commas, supports ranges |
| `--exclude-sizes <sizes>` | Exclude responses by sizes, comma-separated (e.g., `0B,4KB`) |
| `--exclude-text <texts>` | Exclude responses containing the given text (can use multiple flags) |
| `--exclude-regex <regex>` | Exclude responses matching a regular expression |
| `--exclude-redirect <str>` | Exclude responses if this regex/text matches the redirect URL |
| `-m <method>`, `--http-method` | HTTP method (default: GET) |
| `-d <data>`, `--data` | HTTP request body data |
| `-F`, `--follow-redirects` | Follow HTTP redirects |
| `--random-agent` | Use a random User-Agent for each request |
| `--auth <cred>` | Authentication credential (e.g., `user:password` or bearer token) |
| `--auth-type <type>` | Authentication type: `basic`, `digest`, `bearer`, `ntlm`, `jwt`, `oauth2` |
| `--crawl` | Crawl for new paths in responses |
| `--max-rate <n>` | Max requests per second |
| `-o <file>` | Output file path |
| `--format <fmt>` | Output format: `simple`, `plain`, `json`, `xml`, `md`, `csv`, `html`, `sqlite` |
| `-H <header>` | HTTP request header, can use multiple flags |
| `--proxy <url>` | Proxy URL (HTTP/SOCKS), can use multiple flags |
| `--timeout <n>` | Connection timeout |

## Common Commands

```bash
# Basic scan with common extensions
dirsearch -u http://example.com -e php,html,js

# Recursive scan
dirsearch -u http://example.com -e php -r

# Save results to JSON
dirsearch -u http://example.com -e php,html --format json -o results.json

# Custom wordlist
dirsearch -u http://example.com -w /usr/share/wordlists/dirb/big.txt

# Exclude 404 and 403 responses
dirsearch -u http://example.com -e php -x 404,403

# With authentication header
dirsearch -u http://example.com/api -e json -H "Authorization: Bearer <token>"

# Route through Burp Suite proxy
dirsearch -u http://example.com -e php --proxy http://127.0.0.1:8080

# Increase threads for speed
dirsearch -u http://example.com -e php -t 50
```

## Notes & Tips

1. dirsearch includes a built-in wordlist that covers most common paths — no need for SecLists for a quick first scan.
2. Combine with feroxbuster for recursive brute-forcing — feroxbuster is faster for deep recursion, dirsearch has better extension chaining.
3. Use `-e php,html,js,txt,bak,old` to cover most CMS and web framework file extensions in one pass.
4. `--format json -o results.json` enables integration with reporting tools or further processing with `jq`.
5. Add `-x 403` on WAF-protected targets to reduce noise when many paths return access-denied responses.

---

## Official References

- [dirsearch (GitHub)](https://github.com/maurosoria/dirsearch)
- [Kali dirsearch](https://www.kali.org/tools/dirsearch/)
