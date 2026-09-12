# getallurls (gau)

- **Category**: Information Gathering / URL Discovery
- **Risk Level**: 🟢 Low

---

## Description

A tool that fetches known URLs from multiple sources for a given domain. Queries the Wayback Machine, Common Crawl, and Open Threat Exchange (OTX) to build a comprehensive list of historically known URLs without interacting with the target. Essential for discovering hidden endpoints, parameters, old API paths, and potentially sensitive files during reconnaissance. Written in Go and designed for pipeline integration.

## Installation

```bash
sudo apt install getallurls
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-subs` | Include subdomains of the target domain |
| `-providers <list>` | Providers to fetch URLs for (default: `wayback,otx,commoncrawl`) |
| `-json` | Write output as JSON |
| `-o <file>` | Filename to write results to |
| `-p <proxy>` | HTTP proxy to use |
| `-random-agent` | Use random user-agent |
| `-retries <n>` | Number of retries for HTTP client (default: 5) |
| `-v` | Enable verbose mode |
| `-version` | Show gau version |

## Common Commands

```bash
# Basic URL discovery for a domain
echo "example.com" | gau

# Include subdomains
echo "example.com" | gau -subs

# Only fetch from Wayback Machine
echo "example.com" | gau -providers wayback

# Use multiple providers
echo "example.com" | gau -providers "wayback,otx"

# Save results to file
echo "example.com" | gau -o urls.txt

# Output as JSON
echo "example.com" | gau -json

# Use a proxy
echo "example.com" | gau -p http://127.0.0.1:8080

# Filter for specific file types (find potential sensitive files)
echo "example.com" | gau | grep -iE '\.(php|asp|aspx|jsp|json|xml|conf|env|bak|sql)(\?|$)'

# Find URLs with parameters (potential injection points)
echo "example.com" | gau | grep '=' | sort -u

# Chain with ffuf for parameter fuzzing
echo "example.com" | gau | grep '=' | uro | qsreplace FUZZ | ffuf -w - -u FUZZ
```

## Notes & Tips

1. gau is fully passive — it queries archived data and never contacts the target directly.
2. Combine with `uro` to de-duplicate URLs that differ only in parameter values, reducing noise.
3. The output often contains thousands of URLs — filter with `grep`, `sort -u`, and `uro` before passing to active scanners.
4. Configuration file at `~/.gau.toml` allows setting default providers and other options.
5. Default providers are `wayback`, `otx`, and `commoncrawl`. Use `-providers` to select specific ones.
6. Use `-random-agent` to avoid being blocked by archive services during heavy queries.

---

## Official References

- [getallurls / gau (GitHub)](https://github.com/lc/gau)
- [Kali getallurls](https://www.kali.org/tools/getallurls/)
