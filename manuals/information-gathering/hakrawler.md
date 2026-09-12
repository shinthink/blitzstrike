# Hakrawler

- **Category**: Information Gathering / Web Endpoint Discovery
- **Risk Level**: 🟢 Low

---

## Description

A fast web crawler designed for endpoint and asset discovery in web applications. Extracts URLs, JavaScript files, forms, and subdomains from HTML source, JavaScript, robots.txt, and sitemap.xml. Built for pipeline use — reads URLs from stdin and outputs discovered endpoints to stdout, making it easy to chain with subfinder, httpx, and ffuf.

## Installation

```bash
sudo apt install hakrawler
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <n>` | Crawl depth (default: 2) |
| `-u` | Show only unique URLs |
| `-insecure` | Skip TLS certificate verification |
| `-subs` | Follow links to subdomains |
| `-t <n>` | Threads (default: 8) |
| `-proxy <url>` | Proxy URL (e.g., http://127.0.0.1:8080) |
| `-h` | Custom headers (`"Name: value;;Name2: value2"` format, separated by `;;`) |
| `-timeout <n>` | Maximum time to crawl each URL from stdin (seconds) |
| `-s` | Show source of URL (where it was found) |
| `-size <n>` | Page size limit in KB |
| `-json` | Output as JSON |

## Common Commands

```bash
# Crawl a single URL
echo https://example.com | hakrawler

# Crawl to depth 3
echo https://example.com | hakrawler -d 3

# Follow subdomains
echo https://example.com | hakrawler -subs

# Full pipeline: subdomain discovery → probe → crawl
subfinder -d example.com -silent | httpx -silent | hakrawler

# Crawl a list of URLs
cat urls.txt | hakrawler -d 2 -u

# Route through Burp Suite proxy
echo https://example.com | hakrawler -proxy http://127.0.0.1:8080 -insecure

# Extract JavaScript files
echo https://example.com | hakrawler | grep '\.js$'
```

## Notes & Tips

1. Use after subfinder/amass to crawl discovered subdomains for full endpoint mapping.
2. Use `-u` to deduplicate URLs in output — essential for clean pipeline results.
3. Combine with `ffuf` or `gobuster`: hakrawler finds known paths, then brute-force for hidden ones.
4. JavaScript files (`.js`) often contain API endpoints, secrets, and internal paths — grep for `.js` in output.
5. `-subs` follows links to subdomains, which can significantly expand the attack surface beyond the initial domain.

---

## Official References

- [hakrawler (GitHub)](https://github.com/hakluke/hakrawler)
- [Kali hakrawler](https://www.kali.org/tools/hakrawler/)
