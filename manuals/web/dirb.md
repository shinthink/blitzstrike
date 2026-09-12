# DIRB

- **Category**: Web / Directory Brute-Forcing
- **Risk Level**: 🟡 Medium

---

## Description

A classic web content scanner that brute-forces directories and files on web servers using dictionary-based attacks. Uses wordlists to find hidden pages, admin panels, backups, and sensitive files. One of the oldest web directory scanners in Kali, simpler than gobuster/feroxbuster/ffuf but reliable and still widely used. Supports HTTP/HTTPS, custom headers, proxy routing, and extension-based scanning.

## Installation

```bash
sudo apt install dirb -y
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `URL` | Target URL (positional, required) |
| `-o <file>` | Save output to file |
| `-r` | Don't search recursively |
| `-z <ms>` | Add a milliseconds delay to not cause excessive flood |
| `-a <agent>` | Custom User-Agent string |
| `-p <proxy>` | Use proxy (`http://host:port`) |
| `-c <cookie>` | Set a cookie for the HTTP request |
| `-H <header>` | Add custom HTTP header |
| `-w` | Don't stop on WARNING messages |
| `-S` | Silent mode, don't show tested words (for dumb terminals) |
| `-X <exts>` | Append each word with this extension(s) |
| `-x <file>` | Read extensions from file |
| `-N <code>` | Ignore responses with this HTTP status code |
| `-u <user:pass>` | HTTP authentication |
| `-f` | Fine-tuning of NOT_FOUND (404) detection |
| `-i` | Case-insensitive search |
| `-l` | Print "Location" header on redirect responses |
| `-t` | Don't force an ending `/` on URLs |

## Common Commands

### Scenario 1: Basic Directory Scan

```bash
# Scan with default wordlist
dirb http://target.com

# Scan with custom wordlist
dirb http://target.com /usr/share/wordlists/dirb/big.txt
```

### Scenario 2: Extension-Based Scanning

```bash
# Scan for specific file extensions
dirb http://target.com -X .php,.html,.txt

# Scan for backup and sensitive files
dirb http://target.com -X .bak,.old,.zip,.sql,.conf
```

### Scenario 3: Through Proxy

```bash
# Route through Burp Suite
dirb http://target.com -p http://127.0.0.1:8080
```

### Scenario 4: Custom Headers and Cookies

```bash
# Set authentication cookie
dirb http://target.com -c "session=abc123; token=xyz789"

# Add custom header
dirb http://target.com -H "Authorization: Bearer eyJhbGci..."

# HTTP basic authentication
dirb http://target.com -u admin:password123
```

### Scenario 5: Non-Recursive with Delay

```bash
# Disable recursion and add delay to avoid rate limiting
dirb http://target.com -r -z 100
```

### Scenario 6: Save Output

```bash
# Full scan with extensions, save results
dirb http://target.com /usr/share/wordlists/dirb/common.txt \
  -X .php,.html,.txt \
  -o dirb_results.txt
```

### Scenario 7: Silent Scan with Custom User-Agent

```bash
# Reduce output noise and set custom User-Agent
dirb http://target.com -S -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

## Notes & Tips

1. **Wordlist selection**: dirb ships with several built-in wordlists in `/usr/share/wordlists/dirb/` — `common.txt` for quick scans, `big.txt` for comprehensive coverage.
2. **Rate limiting**: Use `-z` to add millisecond delays between requests. Without it, dirb can trigger WAF or rate-limiting rules.
3. **Recursive behavior**: By default dirb recursively scans discovered directories. Use `-r` to disable recursion for faster, shallower scans.
4. **Extension scanning**: The `-X` flag appends extensions to each word. Combine with a good wordlist (e.g., common.txt + `.php,.html,.txt,.bak`) for thorough coverage.
5. **Comparison with modern tools**: gobuster, feroxbuster, and ffuf offer concurrent scanning and are significantly faster. dirb is single-threaded but remains useful for simple, reliable scans where speed is not critical.

---

## Official References

- [dirb SourceForge](https://dirb.sourceforge.net/)
- [Kali Tools - dirb](https://www.kali.org/tools/dirb/)
