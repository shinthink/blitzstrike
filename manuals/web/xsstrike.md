# XSStrike

- **Category**: Web / XSS Detection
- **Risk Level**: 🟡 Medium

---

## Description

An advanced XSS detection tool that analyzes HTML and JavaScript context to generate precise, context-aware payloads — rather than blindly injecting a fixed list of strings. Automatically detects and attempts to bypass WAFs, supports crawling to test all parameters across a site, and includes blind XSS payload injection for backend panel testing.

## Installation

```bash
sudo apt install xsstrike
# Or from GitHub:
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip3 install -r requirements.txt
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Target URL with parameter (e.g., `?q=test`) |
| `--crawl` | Crawl the site and test all found parameters |
| `--blind` | Inject blind XSS payload while crawling |
| `-l <level>` | Level of crawling |
| `-d <seconds>` | Delay between requests (default: 0) |
| `--data <data>` | POST body data |
| `--timeout <n>` | Request timeout in seconds |
| `--proxy` | Use configured proxy (set proxy URL in core/config.py) |
| `--headers <json>` | Add headers |
| `--skip` | Don't ask to continue |
| `--skip-dom` | Skip DOM checking |

## Common Commands

```bash
# Test a single GET parameter
python3 xsstrike.py -u "http://example.com/search?q=test"

# POST request
python3 xsstrike.py -u "http://example.com/comment" --data "body=test&submit=1"

# Crawl the entire site and test all parameters
python3 xsstrike.py -u "http://example.com" --crawl -l 3

# Blind XSS (payload callbacks to an external server)
python3 xsstrike.py -u "http://example.com/contact" --blind

# Route through Burp Suite proxy (configure proxy URL in core/config.py first)
python3 xsstrike.py -u "http://example.com/search?q=test" --proxy

# Add authentication cookie
python3 xsstrike.py -u "http://example.com/profile?id=1" --headers '{"Cookie": "session=abc123"}'
```

## Notes & Tips

1. XSStrike's context-aware payload generation outperforms dalfox for WAF bypass scenarios.
2. Use `--blind` for testing backend admin panels where the XSS output isn't returned in the same response.
3. Combine with dalfox: use dalfox for bulk/fast scanning, XSStrike for deep analysis of specific endpoints.
4. XSStrike automatically detects WAFs and attempts bypass — check the WAF detection output before assuming a parameter is safe.
5. For Bug Bounty: use `--crawl` to maximize coverage; save output for PoC documentation.

---

## Official References

- [XSStrike (GitHub)](https://github.com/s0md3v/XSStrike)
- [Kali xsstrike](https://www.kali.org/tools/xsstrike/)
