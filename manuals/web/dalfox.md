# Dalfox

- **Category**: Web / XSS Detection & Exploitation
- **Risk Level**: 🟡 Medium

---

## Description

A powerful XSS scanning and exploitation tool based on parameter analysis and intelligent payload generation. Supports reflected and DOM-based XSS detection with low false-positive rates and fast speed. Can be integrated into CI/CD pipelines.

## Installation

```bash
sudo apt install dalfox

# From source (requires Go; may timeout in resource-constrained containers):
go install github.com/hahwul/dalfox/v2@latest

# Alternative: download release binary from GitHub
curl -sL https://github.com/hahwul/dalfox/releases/latest/download/dalfox-linux-amd64.tar.gz | tar xz -C /tmp/ && mv /tmp/dalfox-linux-amd64 /usr/local/bin/dalfox
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `url <target>` | Target URL (positional subcommand) |
| `--data <data>` | POST body data |
| `-p <param>` | Specific parameter to test |
| `-H <header>` | Custom HTTP header (key: value) |
| `--cookie <cookie>` / `-C` | Cookie string |
| `-b <url>` | Blind XSS callback URL |
| `--skip-bav` | Skip Bad Action Verification |
| `--skip-mining-all` | Skip all parameter mining |
| `--skip-mining-dict` | Skip dictionary-based parameter mining |
| `--skip-mining-dom` | Skip DOM-based parameter mining |
| `--skip-discovery` | Skip parameter analysis phase |
| `--skip-grepping` | Skip built-in grepping |
| `--skip-headless` | Skip headless browser-based scanning |
| `--skip-xss-scanning` | Skip XSS scanning |
| `--silence` | Only print PoC code and progress (suppress banners and non-PoC output) |
| `--proxy <url>` | HTTP proxy URL |
| `-w <n>` | Number of worker threads (default: 100) |
| `pipe` | Read URLs from stdin (pipeline mode) |
| `file <file>` | Read URLs from file |

## Common Commands

```bash
# Basic XSS scan
dalfox url http://target.com/search?q=test

# POST parameters
dalfox url http://target.com/search --data "q=test&page=1"

# With Cookie
dalfox url http://target.com/ -C "session=abc123"

# Batch URLs
dalfox file urls.txt

# Pipe input
echo "http://target.com/search?q=test" | dalfox pipe

# Scan historical URLs combined with waybackurls
waybackurls target.com | dalfox pipe

# Use proxy
dalfox url http://target.com/search?q=test --proxy http://127.0.0.1:8080

# Specify payload
dalfox url http://target.com/ --custom-payload /tmp/xss_payloads.txt

# JSON output
dalfox url http://target.com/search?q=test --format json -o /tmp/xss_results.json
```

## Notes & Tips

1. dalfox is optimized for speed and low false-positives — it is the preferred tool for bulk XSS scanning; use XSStrike for deep context-aware analysis of specific endpoints.
2. The `-b <url>` flag enables blind XSS with an OOB callback — use your Burp Collaborator URL or interactsh for backend panel testing.
3. Use `pipe` mode with subfinder and httpx for full-pipeline scanning: `subfinder -d example.com | httpx | dalfox pipe`.
4. `--silence` reduces output to PoC code and progress only — suppresses banners and non-PoC output in pipeline use.
5. dalfox automatically identifies reflected parameters before injecting — it is significantly faster than manual parameter-by-parameter testing.
6. **Install failure fallback**: if dalfox cannot be installed (Go compilation timeout, GitHub unreachable), use `xsstrike` (`apt install xsstrike`) as the XSS scanner — it covers reflected, DOM, and blind XSS with context-aware payloads. For bulk URL scanning without dalfox's `pipe` mode, feed URLs to nuclei with `-tags xss`.

---

## Official References

- [dalfox GitHub](https://github.com/hahwul/dalfox)
- [dalfox Documentation](https://dalfox.hahwul.com/page/overview/)
