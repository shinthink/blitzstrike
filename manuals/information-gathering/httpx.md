# httpx-toolkit

- **Category**: Information Gathering / Web Analysis
- **Risk Level**: 🟢

---

## Description

httpx is a fast and multi-purpose HTTP toolkit developed by ProjectDiscovery. It allows running multiple probes against target hosts using the retryablehttp library. It is commonly used for bulk HTTP probing during reconnaissance to identify live hosts, gather response metadata (status codes, titles, technologies), and filter results based on various criteria.

On Kali Linux, the binary is named `httpx-toolkit` to avoid conflicts with the Python `httpx` package (`python3-httpx`).

## Installation

```bash
sudo apt install httpx-toolkit
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l`, `-list` | Input file containing list of hosts to process |
| `-u`, `-target` | Input target host(s) to probe |
| `-p`, `-ports` | Ports to probe (e.g., `-p 80,443,8080,8443`) |
| `-sc`, `-status-code` | Display response status code |
| `-cl`, `-content-length` | Display response content length |
| `-ct`, `-content-type` | Display response content type |
| `-title` | Display page title |
| `-server`, `-web-server` | Display server name |
| `-td`, `-tech-detect` | Display technology in use (wappalyzer dataset) |
| `-ip` | Display host IP address |
| `-cname` | Display host CNAME record |
| `-cdn` | Display CDN/WAF in use |
| `-ss`, `-screenshot` | Enable saving screenshot of the page |
| `-mc`, `-match-code` | Match response with specified status code (e.g., `-mc 200,302`) |
| `-ms`, `-match-string` | Match response with specified string |
| `-mr`, `-match-regex` | Match response with specified regex |
| `-fc`, `-filter-code` | Filter response with specified status code (e.g., `-fc 403,401`) |
| `-fs`, `-filter-string` | Filter response with specified string |
| `-fe`, `-filter-regex` | Filter response with specified regex |
| `-o`, `-output` | File to write output results |
| `-j`, `-json` | Write output in JSONL(ines) format |
| `-csv` | Write output in CSV format |
| `-sr`, `-store-response` | Store HTTP response to output directory |
| `-srd`, `-store-response-dir` | Store HTTP response to custom directory |
| `-threads` | Number of threads to use (default: 50) |
| `-rl`, `-rate-limit` | Maximum requests to send per second (default: 150) |
| `-rlm`, `-rate-limit-minute` | Maximum requests per minute per host |
| `-H`, `-header` | Custom HTTP headers to send with request |
| `-http-proxy`, `-proxy` | HTTP proxy to use for requests |
| `-fr`, `-follow-redirects` | Follow HTTP redirects |
| `-timeout` | Timeout in seconds (default: 10) |
| `-retries` | Number of retries for failed requests |
| `-random-agent` | Enable random User-Agent (default: true) |
| `-version` | Display httpx version |
| `-v`, `-verbose` | Verbose mode |
| `-silent` | Silent mode |
| `-nc`, `-no-color` | Disable colors in output |

## Common Commands

### Scenario 1: Probe a single target for basic info

```bash
httpx-toolkit -u https://example.com -sc -title -td -server
```

### Scenario 2: Bulk probe hosts from a file

```bash
httpx-toolkit -l hosts.txt -sc -title -ip -o results.txt
```

### Scenario 3: Filter out 403/404 responses and show only live pages

```bash
cat subdomains.txt | httpx-toolkit -sc -title -fc 403,404
```

### Scenario 4: Match only specific status codes

```bash
httpx-toolkit -l targets.txt -mc 200,301,302 -title -server
```

### Scenario 5: Technology detection with JSON output

```bash
httpx-toolkit -l hosts.txt -td -cdn -json -o tech-results.json
```

### Scenario 6: Use with subfinder pipeline

```bash
subfinder -d example.com -silent | httpx-toolkit -sc -title -td
```

### Scenario 7: Screenshot live hosts

```bash
httpx-toolkit -l hosts.txt -ss -sc -title -o live-hosts.txt
```

### Scenario 8: Rate-limited scan through a proxy

```bash
httpx-toolkit -l targets.txt -sc -title -proxy http://127.0.0.1:8080 -rl 10 -threads 5
```

## Notes & Tips

1. The binary is `httpx-toolkit` on Kali, not `httpx`. Running `httpx` may invoke the unrelated Python httpx library.
2. httpx accepts input from stdin, making it ideal for piping from tools like `subfinder`, `amass`, or `cat`.
3. Use `-json` output for programmatic parsing and integration with other tools.
4. Combine `-td` (tech detect) with `-cdn` to quickly identify WAF-protected targets during recon.
5. The `-follow-redirects` flag is useful for catching targets that redirect HTTP to HTTPS or to different subdomains.
6. Default thread count (50) and rate limit (150 req/s) are aggressive; reduce with `-threads` and `-rl` when scanning sensitive targets.
7. Use `-store-response` to save full HTTP responses for offline analysis or evidence collection.
8. Random User-Agent is enabled by default, which helps avoid simple bot detection.

---

## Official References

- [httpx - GitHub](https://github.com/projectdiscovery/httpx)
- [httpx - ProjectDiscovery Documentation](https://docs.projectdiscovery.io/tools/httpx/overview)
