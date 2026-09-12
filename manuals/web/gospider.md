# GoSpider

- **Category**: Web / Crawling & Endpoint Discovery
- **Risk Level**: 🟢 Low

---

## Description

A fast web spider written in Go for discovering URLs, JavaScript endpoints, subdomains, and AWS S3 buckets. Also queries historical URLs from the Wayback Machine, Common Crawl, and VirusTotal. Complements hakrawler by adding third-party historical URL sources and supporting parallel multi-site crawling.

## Installation

```bash
sudo apt install gospider
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-s <url>` | Single site to crawl |
| `-S <file>` | File of sites to crawl (one per line) |
| `-d <n>` | Crawl depth (default: 1) |
| `-t <n>` | Number of concurrent sites (default: 1) |
| `-c <n>` | Concurrent requests per site (default: 5) |
| `-o <dir>` | Output directory |
| `--sitemap` | Parse sitemap.xml |
| `--robots` | Parse robots.txt (enabled by default) |
| `-a` / `--other-source` | Find URLs from 3rd party (Archive.org, CommonCrawl.org, VirusTotal.com) |
| `--proxy <url>` | HTTP proxy URL |
| `-q` | Quiet mode |
| `--cookie <string>` | Cookie to use for requests |
| `-H <header>` | Custom header(s) to add |

## Common Commands

```bash
# Basic crawl of a single site
gospider -s http://example.com

# Crawl to depth 3 with sitemap and robots
gospider -s http://example.com -d 3 --sitemap --robots

# Include historical URLs from external sources
gospider -s http://example.com --other-source

# Crawl multiple sites in parallel
gospider -S sites.txt -t 5 -c 10

# Save output to directory
gospider -s http://example.com -o ./results

# Route through Burp Suite proxy
gospider -s http://example.com --proxy http://127.0.0.1:8080 -d 2
```

## Notes & Tips

1. Use --other-source to retrieve URLs from the Wayback Machine, CommonCrawl, and VirusTotal — often reveals endpoints still alive but no longer in navigation.
2. gospider automatically parses JavaScript files for embedded API endpoints, tokens, and internal paths.
3. gospider supports parallel multi-site crawling with -S and -t, making it suitable for bulk target assessments.
4. Combine with crlfuzz, dalfox, or sqlmap — pipe discovered URLs into injection scanners.
5. For maximum endpoint coverage: gospider (crawling + historical) + hakrawler (JS/sitemap) + ffuf (brute-force).

---

## Official References

- [gospider (GitHub)](https://github.com/jaeles-project/gospider)
- [Kali gospider](https://www.kali.org/tools/gospider/)
