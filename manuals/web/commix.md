# Commix

- **Category**: Web / Command Injection
- **Risk Level**: 🔴 High

---

## Description

An automated command injection vulnerability detection and exploitation tool. Supports multiple injection points including GET/POST/Cookie/HTTP Headers, covering time-based, output-based, file-based, and other injection techniques. A specialized command injection tool — analogous to sqlmap for SQL injection.

## Installation

```bash
sudo apt install commix
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--url URL` | Target URL |
| `--data DATA` | POST data |
| `--cookie COOKIE` | Cookie |
| `-p PARAM` | Testable parameter(s) |
| `--technique TECH` | Specify injection technique(s) to use |
| `--level=LEVEL` | Level of tests to perform (1-3, default: 1) |
| `--os=OS` | Force back-end operating system (e.g. 'Windows' or 'Unix') |
| `--os-cmd CMD` | Execute a single operating system command |
| `-r FILE` | Read from HTTP request file |
| `--proxy PROXY` | Use a proxy to connect to the target URL |
| `--random-agent` | Use a randomly selected HTTP User-Agent header |
| `--batch` | Never ask for user input, use the default behaviour |
| `--crawl=<depth>` | Crawl the website starting from target URL |
| `-l <logfile>` | Parse target URLs from HTTP proxy log file |

## Common Commands

```bash
# Detect GET parameter
commix --url="http://target.com/ping?host=INJECT_HERE"

# POST parameter
commix --url="http://target.com/" --data="ip=INJECT_HERE"

# Auto-detect parameter (without specifying INJECT_HERE)
commix --url="http://target.com/ping?host=127.0.0.1"

# Execute a command
commix --url="http://target.com/ping?host=127.0.0.1" --os-cmd="id"

# From Burp request file
commix -r /tmp/request.txt

# Use proxy (through Burp)
commix --url="http://target.com/ping?host=127.0.0.1" --proxy="http://127.0.0.1:8080"
```

## Notes & Tips

1. Always run commix with `--level=2` or higher for thorough injection testing — level 1 may miss indirect injection vectors.
2. Use `--os=linux` or `--os=windows` to limit payloads to the target OS and reduce noise.
3. The `--technique` option filters which injection techniques are tested — use `t` (time-based) when error-based and blind methods fail.
4. Commix can use a saved HTTP request file from Burp Suite with `-r REQUESTFILE` — useful for complex authenticated requests.
5. For WAF bypass, try `--tamper=space2ifs` or other tamper scripts; commix supports tamper scripts similar to sqlmap.

---

## Official References

- [commix GitHub](https://github.com/commixproject/commix)
