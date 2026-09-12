# WhatWeb

- **Category**: Information Gathering / Web Fingerprinting
- **Risk Level**: 🟢 Low

---

## Description

WhatWeb is a web application fingerprinting tool that identifies the technology stack used by web applications, including CMS (WordPress, Joomla, Drupal, etc.), blog platforms, analytics tools, JavaScript libraries, web servers, and embedded devices. It has over 1800 plugins and performs identification by analyzing HTTP headers, HTML content, cookies, URL patterns, and other dimensions.

## Installation

```bash
whatweb --version

sudo apt install whatweb
gem install whatweb
```

## Parameter Reference

### Aggression Levels

| Level | Description | Risk |
|-------|-------------|------|
| 1 | Stealthy (default): single HTTP request per URL | Very Low |
| 2 | Unused (same behavior as level 1 in practice) | Very Low |
| 3 | Aggressive: multiple requests including additional path probing | Medium |
| 4 | Heavy: very large number of requests per target | High |

| Parameter | Description |
|-----------|-------------|
| `<target>` | URL / IP / CIDR / file Example: `http://example.com` |
| `-i <file>` | Read targets from file Example: `-i targets.txt` |
| `-a <level>` | Set the aggression level (default: 1) |
| `--log-verbose <file>` | Verbose log output |
| `--log-xml <file>` | Log XML format |
| `--log-json <file>` | Log JSON format |
| `--log-json-verbose <file>` | Log JSON verbose format |
| `--log-brief <file>` | Log brief, one-line output |
| `--log-errors <file>` | Log errors |
| `-q` | Do not display brief logging to STDOUT |
| `-v` | Verbose output includes plugin descriptions |
| `--no-errors` | Suppress error messages |
| `-t <threads>` | Number of simultaneous threads (default: 25) |
| `--open-timeout <sec>` | Time in seconds (default: 15) |
| `--read-timeout <sec>` | Time in seconds (default: 30) |
| `--max-redirects <count>` | Maximum number of redirects (default: 10) |
| `-p <plugin>` | Select plugins (comma-delimited set) |
| `--list-plugins` | List all plugins |
| `--info-plugins [plugin]` | List all plugins with detailed information |
| `--dorks [plugin]` | List Google dorks for the selected plugin |
| `-U <User-Agent>` | Identify as AGENT instead of WhatWeb/0.6.3 |
| `--user-agent <string>` | Identify as AGENT instead of WhatWeb/0.6.3 |
| `--user <user:pass>` | HTTP basic authentication |
| `--proxy <proxy>` | Set proxy hostname and port |
| `--proxy-user <user:pass>` | Set proxy user and password |
| `--cookie <cookie>` | Use cookies (e.g. 'name=value; name2=value2') |
| `--header <header>` | Add an HTTP header (e.g. "Foo:Bar") |
| `--follow-redirect <rule>` | Control when to follow redirects |
| `--url-prefix <prefix>` | Add a prefix to target URLs |
| `--url-suffix <suffix>` | Add a suffix to target URLs |
| `--url-pattern <pattern>` | Insert the targets into a URL |
| `--colour <value>` | Control whether colour is used (always/never/auto) |
| `--colour=never` | Disable colored output |

## Common Commands

### Basic Identification

```bash
# Basic web fingerprinting
whatweb http://example.com

# HTTPS target
whatweb https://example.com

# Verbose output
whatweb -v http://example.com

# Quiet mode (results only)
whatweb -q http://example.com
```

### Batch Scanning

```bash
# Scan IP range
whatweb 192.168.1.0/24

# Read targets from file (one URL per line)
whatweb -i targets.txt --log-json results.json

# Concurrent scanning (50 threads)
whatweb -t 50 -i targets.txt
```

### Aggressive Scanning

```bash
# Aggressive mode (more probing, detects more technologies)
whatweb -a 3 http://example.com

# Maximum aggression (comprehensive detection)
whatweb -a 4 http://example.com
```

### Output Formats

```bash
# JSON output (easy to parse)
whatweb --log-json results.json http://example.com

# XML output
whatweb --log-xml results.xml http://example.com

# Verbose log
whatweb --log-verbose results.txt http://example.com
```

### Authentication and Proxy

```bash
# HTTP basic authentication
whatweb --user admin:password http://example.com/admin

# Use cookie
whatweb --cookie "session=abc123" http://example.com

# Through Burp proxy
whatweb --proxy 127.0.0.1:8080 http://example.com

# Custom User-Agent
whatweb -U "Mozilla/5.0 (Custom)" http://example.com
# or equivalently:
whatweb --user-agent "Mozilla/5.0 (Custom)" http://example.com
```

### Integration with Other Tools

```bash
# Batch identification from amass results
# Note: amass outputs one subdomain per line to stdout; status messages go to stderr
amass enum -passive -d example.com | sed 's/^/http:\/\//' | whatweb -i /dev/stdin

# To probe both http and https, use httpx first:
amass enum -passive -d example.com | httpx -o /tmp/alive.txt
whatweb -i /tmp/alive.txt --log-json whatweb_results.json

# Combined with httprobe
cat subdomains.txt | httprobe | whatweb -i /dev/stdin --log-json whatweb_results.json
```

## Notes & Tips

1. **Version Information**: Some version information may be hidden by system administrators; results may not be complete
2. **False Positives**: Some plugins may produce false positives; important findings should be manually verified
3. **WAF Bypass**: If the target has a WAF, it may interfere with identification results; consider using `-a 1` to reduce aggression
4. **HTTPS**: Automatically follows redirects; use `--max-redirects` to control

---

## Official References

- [WhatWeb GitHub](https://github.com/urbanadventurer/WhatWeb)
