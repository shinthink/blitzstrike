# CertGraph

- **Category**: Information Gathering / Certificate Transparency
- **Risk Level**: 🟢 Low

---

## Description

certgraph maps SSL/TLS certificate relationships by crawling certificate transparency logs and direct TLS connections. It builds a graph of related domains by following Subject Alternative Names (SANs) across certificates to a configurable depth. Outputs a text-based graph by default, with JSON output available for programmatic processing. Useful for discovering related domains, subsidiaries, and shared-infrastructure targets. Written in Go.

## Installation

```bash
sudo apt install certgraph

certgraph -h

# Or install via Go
go install github.com/lanrat/certgraph@latest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<domain>` | Seed domain to start graph crawling (positional) |
| `-depth <n>` | Maximum crawl depth (default: 5) |
| `-driver <name>` | Certificate source driver: `http` (default), `crtsh`, `google`, or `smtp` |
| `-json` | Output results in JSON format |
| `-ct-subdomains` | Include subdomains from CT logs |
| `-cdn` | Include CDN domains (excluded by default) |
| `-timeout <seconds>` | TCP timeout in seconds (default: 10) |
| `-parallel <n>` | Number of parallel certificate fetches (default: 10) |
| `-save <dir>` | Save certificates to directory in PEM format |
| `-details` | Print detailed certificate information |
| `-dns` | Check DNS for domains |
| `-verbose` | Verbose logging |

## Common Commands

### Scenario 1: Basic Certificate Graph

```bash
# Generate a certificate relationship graph
certgraph example.com

# Limit crawl depth
certgraph -depth 2 example.com

# Save certificates to folder in PEM format
certgraph -save certs/ example.com
```

### Scenario 2: Driver Selection

```bash
# Use crt.sh CT logs (passive, no direct connections)
certgraph -driver crtsh example.com

# Use direct HTTP connections (default)
certgraph -driver http example.com

# Use Google CT data
certgraph -driver google example.com

# Query SMTP servers for certificates
certgraph -driver smtp example.com
```

### Scenario 3: JSON Output

```bash
# Output in JSON format for programmatic processing
certgraph -json example.com

# Save JSON to file
certgraph -json example.com > certgraph_results.json

# JSON output with detailed certificate info
certgraph -json -details example.com
```

### Scenario 4: Comprehensive Discovery

```bash
# Include subdomains from CT logs
certgraph -ct-subdomains example.com

# Include CDN domains (normally excluded)
certgraph -cdn example.com

# Deep crawl with subdomains and CDN
certgraph -depth 3 -ct-subdomains -cdn example.com
```

### Scenario 5: Performance Tuning

```bash
# Increase parallel connections for faster scanning
certgraph -parallel 20 -timeout 10 example.com

# Verbose output for debugging
certgraph -verbose -depth 2 example.com
```

## Notes & Tips

1. The default depth of 5 can produce very large graphs for major domains. Start with `-depth 2` and increase as needed.
2. The `crtsh` driver is passive and does not make direct connections to targets — use it when stealth is required.
3. The `http` driver (default) connects directly to each discovered domain on port 443 — this generates traffic visible to the target.
4. CDN domains (Cloudflare, Akamai, etc.) are excluded by default because they share certificates across many unrelated sites. Use `-cdn` only when CDN relationships are relevant.
5. Use `-json` output piped to `jq` for programmatic filtering and integration with other tools.

---

## Official References

- [certgraph (GitHub)](https://github.com/lanrat/certgraph)
- [Kali certgraph](https://www.kali.org/tools/certgraph/)
