# katana

- **Category**: Web / Crawling & Endpoint Discovery
- **Risk Level**: 🟡 Medium

---

## Description

Katana is ProjectDiscovery's CLI web crawling and spidering framework. It supports standard HTTP crawling, optional headless browser crawling, JavaScript endpoint parsing, form extraction, scope control, stdin/list input, file output, and JSONL output. For agent workflows, use it to turn live web targets into endpoint lists before parameter discovery, nuclei scans, DAST runs, and manual injection testing.

## Installation

```bash
# Kali apt install (recommended)
sudo apt install katana

# Upstream Go install
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# Optional Docker image
docker pull projectdiscovery/katana:latest

katana -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Target URL or comma-separated URLs to crawl |
| `-list <file>` | Read target URLs from a file |
| `-d <n>` | Maximum crawl depth |
| `-jc, -js-crawl` | Parse and crawl endpoints found in JavaScript files |
| `-jsl, -jsluice` | Enable jsluice parsing for JS endpoint extraction (memory intensive) |
| `-xhr, -xhr-extraction` | Extract XHR request URL and method into JSONL output |
| `-kf <mode>` | Crawl known files such as `robotstxt`, `sitemapxml`, or `all` |
| `-fx, -form-extraction` | Extract form, input, textarea, and select elements in JSONL output |
| `-td, -tech-detect` | Enable technology detection |
| `-H <header>` | Add a custom HTTP header or cookie |
| `-proxy <url>` | Send requests through an HTTP/SOCKS5 proxy |
| `-hl, -headless` | Enable headless hybrid crawling |
| `-sc, -system-chrome` | Use the system Chrome browser for headless crawling |
| `-nos, -no-sandbox` | Start headless Chrome with no sandbox, often needed when running as root |
| `-fs <field>` | Set field scope, such as `rdn`, `fqdn`, or `dn` |
| `-cs <regex-or-file>` | Restrict crawling to matching in-scope URLs |
| `-cos <regex-or-file>` | Exclude out-of-scope URLs |
| `-em <ext>` | Match output by extension |
| `-ef <ext>` | Filter output by extension |
| `-mdc <dsl>` | Match responses with a DSL-based condition |
| `-fdc <dsl>` | Filter responses with a DSL-based condition |
| `-c <n>` | Number of concurrent fetchers |
| `-rl <n>` | Maximum requests per second |
| `-s <strategy>` | Visit strategy: `depth-first` (default), `breadth-first` |
| `-iqp` | Ignore crawling same path with different query-param values |
| `-timeout <n>` | Time to wait for request in seconds (default: 10) |
| `-retry <n>` | Number of times to retry the request (default: 1) |
| `-resume <file>` | Resume scan using resume.cfg |
| `-o <file>` | Write output to file |
| `-j, -jsonl` | Write JSONL output |
| `-silent` | Print output only, suitable for pipelines |

## Common Commands

```bash
# Crawl one web target
katana -u https://target.com -d 3 -silent -o /tmp/katana-urls.txt

# Crawl a list of live URLs discovered by httpx
katana -list /tmp/alive.txt -d 2 -silent -o /tmp/katana-alive.txt

# Parse JavaScript and known files
katana -u https://target.com -d 3 -jc -kf all -silent -o /tmp/katana-js.txt

# JSONL output with form extraction for agent parsing
katana -u https://target.com -d 3 -fx -j -o /tmp/katana.jsonl

# Headless crawl for JavaScript-heavy applications
katana -u https://app.target.com -headless -system-chrome -no-sandbox -d 2 -j -o /tmp/katana-headless.jsonl

# Keep crawl inside an explicit scope
katana -u https://target.com -fs fqdn -cos logout -d 3 -silent

# Crawl through an intercepting proxy
katana -u https://target.com -proxy http://127.0.0.1:8080 -d 2 -j -o /tmp/katana-proxy.jsonl

# Pipeline discovered endpoints into nuclei
katana -list /tmp/alive.txt -d 2 -silent | nuclei -o /tmp/nuclei-katana.txt
```

## Notes & Tips

1. Use standard mode first because it is faster; use headless mode when JavaScript rendering or browser-like behavior is required.
2. Keep `-fs`, `-cs`, and `-cos` explicit on broad targets so the crawler does not leave the authorized scope.
3. Use `-j` with `-fx` when an agent needs structured endpoint and form data.
4. Combine `-jc` and `-kf all` to improve API and hidden endpoint coverage.
5. Tune `-rl`, `-c`, and `-d` carefully on production targets; crawling can generate substantial traffic.

---

## Official References

- [Katana Documentation](https://docs.projectdiscovery.io/tools/katana/overview)
- [Katana GitHub](https://github.com/projectdiscovery/katana)
