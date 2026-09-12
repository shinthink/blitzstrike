# CRLFuzz

- **Category**: Web / Injection Testing
- **Risk Level**: 🟢 Low

---

## Description

A fast Go-based scanner for CRLF (Carriage Return Line Feed) injection vulnerabilities. Tests whether user-supplied input can inject CR+LF characters into HTTP headers, potentially enabling response splitting, header injection, and cookie injection attacks. Pipeline-friendly — reads URLs from stdin or a file.

## Installation

```bash
sudo apt install crlfuzz
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Define single URL to fuzz |
| `-l <file>` | Fuzz URLs within file |
| `-c <n>` | Set the concurrency level (default: 20) |
| `-o <file>` | Save results to file |
| `-s` | Silent mode (output only vulnerable URLs) |
| `-x` / `--proxy <url>` | Use proxy to fuzz |
| `-X` / `--method <method>` | Specify request method to use (default: GET) |
| `-d` / `--data <body>` | Request body data |
| `-H` / `--header <header>` | Pass custom header to target |
| `-v` / `--verbose` | Verbose mode, show error details |
| `-V` / `--version` | Show current CRLFuzz version |

## Common Commands

```bash
# Test a single URL
crlfuzz -u "http://example.com/page?param=value"

# Test a list of URLs
crlfuzz -l urls.txt

# Silent mode (only show vulnerable URLs)
crlfuzz -l urls.txt -s

# Save results to file
crlfuzz -l urls.txt -o vulnerable.txt

# Route through Burp Suite proxy
crlfuzz -u "http://example.com/?q=test" --proxy http://127.0.0.1:8080
```

## Notes & Tips

1. CRLF injection allows attackers to add arbitrary HTTP headers to responses, enabling XSS via injected Set-Cookie or redirect via Location headers.
2. Test all URL parameters, especially those reflected in response headers (redirects, custom headers).
3. Combine with gospider or hakrawler to discover all URLs, then pipe through crlfuzz.
4. A successful injection shows the CR+LF sequence reflected in a response header.
5. Many WAFs detect standard CRLF payloads — try alternate encodings if blocked.

---

## Official References

- [CRLFuzz (GitHub)](https://github.com/dwisiswant0/crlfuzz)
- [Kali crlfuzz](https://www.kali.org/tools/crlfuzz/)
