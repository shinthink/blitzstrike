# WPScan

- **Category**: Web / CMS Scanning
- **Risk Level**: 🟡 Medium

---

## Description

A security scanning tool designed specifically for WordPress. Can enumerate users, plugins, and themes; detect known vulnerabilities; and support password brute-forcing. The standard tool for assessing the security of WordPress sites.

## Installation

```bash
sudo apt install wpscan
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--url URL` | The URL of the blog to scan (allowed protocols: http, https) |
| `--enumerate u` | Enumerate user IDs (default range: 1-10) |
| `--enumerate p` | Enumerate popular plugins |
| `--enumerate ap` | Enumerate all plugins |
| `--enumerate vp` | Enumerate vulnerable plugins only |
| `--enumerate t` | Enumerate popular themes |
| `--enumerate at` | Enumerate all themes |
| `--enumerate vt` | Enumerate vulnerable themes only |
| `--enumerate tt` | Enumerate timthumbs |
| `--enumerate cb` | Enumerate config backups |
| `--enumerate dbe` | Enumerate database exports |
| `--enumerate m` | Enumerate media IDs |
| `--detection-mode` | Detection mode: mixed (default), passive, aggressive |
| `--passwords FILE` | List of passwords to use during the password attack |
| `--usernames LIST` | List of usernames to use during the password attack |
| `--api-token TOKEN` | WPScan API Token to display vulnerability data |
| `--proxy URL` | Supported protocols depend on the cURL installed |
| `-o FILE` | Output file |
| `--format FORMAT` | Output format: cli-no-color, json, cli |

## Common Commands

```bash
# Basic scan
wpscan --url http://target.com

# Enumerate everything (users + plugins + themes)
wpscan --url http://target.com --enumerate u,p,t

# Enumerate vulnerable plugins only (reduce noise)
wpscan --url http://target.com --enumerate vp

# Passive mode (reduce request volume)
wpscan --url http://target.com --enumerate p --detection-mode passive

# Password brute-force (need to enumerate usernames first)
wpscan --url http://target.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt

# Use API Token (recommended; improves vulnerability coverage)
wpscan --url http://target.com --api-token YOUR_TOKEN --enumerate vp

# Output JSON report
wpscan --url http://target.com --enumerate u,vp --format json -o /tmp/wpscan_result.json
```

## Notes & Tips
1. Free API Token allows 25 API requests per day; recommended to register at: https://wpscan.com/register — without a token, vulnerability coverage is significantly reduced.
2. Aggressive mode generates large numbers of requests; can easily trigger WAF or IP banning — use `--detection-mode passive` first to minimize footprint.
3. After finding usernames, combine with hydra for more flexible brute-forcing with custom wordlists and rate control.
4. Always enumerate plugins (`-e vp`) separately from users (`-e u`) — vulnerable plugins are the most common WordPress attack vector.
5. `--format json` output enables automated processing; pipe to `jq` to extract specific plugin versions or CVE identifiers for chaining into nuclei or manual exploitation.

---

## Official References

- [WPScan GitHub](https://github.com/wpscanteam/wpscan)
- [WPScan Vulnerability Database & API](https://wpscan.com/)
