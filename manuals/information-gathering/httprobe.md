# httprobe

- **Category**: Information Gathering / HTTP Probing
- **Risk Level**: 🟢 Low

---

## Description

A fast HTTP/HTTPS probing tool that takes a list of domains or subdomains on stdin and outputs those with running HTTP/S servers. Designed as a pipeline filter between subdomain discovery and web scanning — quickly identifies which hosts are actually serving web content. Written in Go by @tomnomnom; lightweight and single-purpose compared to the more feature-rich httpx.

## Installation

```bash
sudo apt install httprobe
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-p <proto:port>` | Additional port to probe as protocol:port pair (can be repeated) |
| `-s` | Skip default ports (80/443), only probe explicitly specified ports |
| `-t <ms>` | Timeout in milliseconds (default: 10000) |
| `-c <n>` | Concurrency level (default: 20) |
| `-prefer-https` | If HTTPS responds, do not print HTTP result for same host |

## Common Commands

```bash
# Probe subdomains for HTTP/HTTPS
cat subdomains.txt | httprobe

# Probe with additional ports
cat subdomains.txt | httprobe -p http:8080 -p https:8443

# Only probe non-standard ports
cat subdomains.txt | httprobe -s -p http:8080 -p https:8443 -p http:9090

# Increase concurrency for large lists
cat subdomains.txt | httprobe -c 50

# Set shorter timeout
cat subdomains.txt | httprobe -t 5000

# Prefer HTTPS to reduce duplicate results
cat subdomains.txt | httprobe -prefer-https

# Full pipeline: discover → probe → scan
subfinder -d example.com -silent | httprobe -prefer-https | nuclei -t cves/
```

## Notes & Tips

1. httprobe sends actual HTTP requests to targets — this is active reconnaissance, not passive.
2. Use `-prefer-https` to avoid duplicate entries when both HTTP and HTTPS respond on the same host.
3. For large-scale probing with more features (tech detection, status codes, titles), use `httpx` instead.
4. httprobe's strength is simplicity — stdin/stdout, no configuration, fast. Ideal for quick pipeline filtering.
5. Adjust `-c` (concurrency) and `-t` (timeout) based on network conditions; high concurrency on slow networks causes timeouts.

---

## Official References

- [httprobe (GitHub)](https://github.com/tomnomnom/httprobe)
- [Kali httprobe](https://www.kali.org/tools/httprobe/)
