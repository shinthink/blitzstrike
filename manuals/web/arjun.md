# Arjun

- **Category**: Web / HTTP Parameter Discovery
- **Risk Level**: 🟡 Medium

---

## Description

An HTTP parameter discovery tool that finds hidden parameters in URL or API endpoints through dictionary brute-forcing and intelligent analysis. Supports GET/POST/JSON/XML formats. Discovered hidden parameters are commonly followed up with sqlmap, commix, and other tools for further testing.

## Installation

```bash
# Kali apt install (recommended)
sudo apt install arjun

# Or via pip
pip install arjun
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-u URL` | Target URL |
| `-i FILE` | Import target URLs from file |
| `-m METHOD` | HTTP method (GET/POST/JSON/XML) |
| `-w FILE` | Wordlist file path (default: {arjundir}/db/large.txt) |
| `-t N` | Concurrent threads (default 5) |
| `--include PARAMS` | Include this data in every request |
| `--headers DICT` | Add headers (separate multiple headers with a new line) |
| `--passive` | Passive mode (collect params from Wayback Machine, CommonCrawl, OTX) |
| `--stable` | Prefer stability over speed |
| `-c N` | Chunk size: number of parameters to send at once |
| `-oJ FILE` | JSON format output to file |
| `-oT FILE` | Plain text output to file |

## Common Commands

```bash
# Discover GET parameters
arjun -u http://target.com/search

# Discover POST parameters
arjun -u http://target.com/api -m POST

# JSON body parameters
arjun -u http://target.com/api -m JSON

# Batch URLs
arjun -i urls.txt

# Custom wordlist
arjun -u http://target.com/ -w /path/to/params.txt

# With Cookie (JSON dict format required)
arjun -u http://target.com/ --headers '{"Cookie": "session=abc123"}'

# JSON output
arjun -u http://target.com/ -oJ /tmp/params.json

# Concurrent
arjun -u http://target.com/ -t 10
```

## Notes & Tips

1. Always use arjun on every discovered endpoint — hidden parameters are frequently the entry point for injection vulnerabilities.
2. The JSON wordlist (`-m JSON`) tests parameters in JSON request bodies — essential for modern REST APIs.
3. Combine with ffuf for comprehensive discovery: arjun finds parameter names, ffuf brute-forces parameter values.
4. `--passive` mode queries APIs (CommonCrawl, OTX, Wayback Machine) for known parameters without sending requests to the target.
5. Filter response size changes carefully — legitimate parameters often cause minor size differences that trigger false positives.

---

## Official References

- [Arjun GitHub](https://github.com/s0md3v/Arjun)
