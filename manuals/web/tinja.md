# TInjA

- **Category**: Web / Template Injection
- **Risk Level**: 🔴 High

---

## Description

An automated SSTI (Server-Side Template Injection) and CSTI (Client-Side Template Injection) detection tool. Identifies template injection vulnerabilities across 44 template engines in 8 languages including Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, and others. Supports GET and POST parameters, cookies, and custom headers as injection points.

## Installation

```bash
sudo apt install tinja -y

# Or install via Go
go install -v github.com/Hackmanit/TInjA@latest
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `url <target>` | Subcommand with target URL as positional argument (use multiple times or `file:/path` for file input) |
| `--config <path>` | Set the path for a config file to be read |
| `-c, --cookie <cookies>` | Add custom cookie(s) |
| `-H, --header <header>` | Add custom header(s) |
| `--proxyurl <url>` | Set the URL of the proxy |
| `--proxycertpath <path>` | Set the path for the certificate of the proxy |
| `--csti` | Enable scanning for Client-Side Template Injections using a headless browser |
| `-r, --ratelimit <n>` | Requests per second (0 = infinite, default: 0) |
| `--reportpath <path>` | Set the path for a report to be generated |
| `--testheaders` | Headers to test (e.g., `Host,Origin,X-Forwarded-For`) |
| `--timeout <seconds>` | Seconds until timeout (default: 15) |
| `--useragentchrome` | Set Chrome as user-agent (default: `TInjA v1.2.0`) |
| `-v, --verbosity <n>` | Verbosity of output: 0 = quiet, 1 = default, 2 = verbose |

## Common Commands

### Scenario 1: Basic URL Scan

```bash
# Test GET parameters for SSTI
tinja url "http://target.com/page?name=test"
```

### Scenario 2: POST Data Test

```bash
# Test POST parameters (include data in the URL query or use a config file)
tinja url "http://target.com/render?template=test&name=value"
```

### Scenario 3: With Cookies

```bash
# Scan with authentication cookies
tinja url "http://target.com/page?name=test" \
  -c "session=abc123; token=xyz789"
```

### Scenario 4: Through Proxy

```bash
# Route through Burp Suite proxy
tinja url "http://target.com/page?name=test" \
  --proxyurl http://127.0.0.1:8080
```

### Scenario 5: Multiple URLs

```bash
# Scan multiple URLs
tinja url "http://target.com/page?name=test" "http://target.com/other?q=test"

# Scan URLs from a file
tinja url "file:/tmp/urls.txt"
```

### Scenario 6: Enable CSTI Detection

```bash
# Enable both SSTI and CSTI scanning
tinja url "http://target.com/page?name=test" --csti
```

## Notes & Tips

1. **Template engine coverage**: TInjA supports 44 template engines across 8 languages (.NET, Elixir, Go, Java, JavaScript, PHP, Python, Ruby).
2. **SSTI vs CSTI**: SSTI scanning is always enabled by default. Add `--csti` to also scan for client-side template injection.
3. **Proxy integration**: Use `--proxyurl` with Burp Suite to inspect and replay injection payloads for manual analysis. Add `--proxycertpath` when scanning HTTPS targets through the proxy.
4. **False positives**: Template injection detection relies on mathematical expression evaluation (e.g., `{{7*7}}`). Some application logic may legitimately evaluate expressions — verify findings manually.
5. **Confirmed SSTI typically leads to RCE**: If TInjA confirms a server-side template injection, manual exploitation can often achieve code execution. Ensure proper authorization before attempting exploitation.

---

## Official References

- [TInjA GitHub](https://github.com/Hackmanit/TInjA)
- [Kali Tools - tinja](https://www.kali.org/tools/tinja/)
