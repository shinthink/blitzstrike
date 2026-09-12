# CMSeeK

- **Category**: Web / CMS Detection
- **Risk Level**: 🟡 Medium

---

## Description

A CMS (Content Management System) detection and basic vulnerability scanning tool covering 180+ CMS types — WordPress, Joomla, Drupal, Magento, and more. Identifies the CMS version, enumerates users, and lists known vulnerabilities for the detected version. Use it when the target CMS is unknown; pivot to wpscan for deeper WordPress-specific enumeration.

## Installation

```bash
sudo apt install cmseek
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u <url>` | Target URL |
| `-l <file>` | File of target URLs (comma separated) |
| `-i <cms>` | CMS IDs to skip (avoid false positives, comma separated) |
| `--strict-cms <cms>` | Only check against specified CMS IDs (comma separated) |
| `--skip-scanned` | Skip target if CMS was previously detected |
| `--light-scan` | Skip deep scan, CMS and version detection only |
| `-o`, `--only-cms` | Only detect CMS, ignore deep scan and version detection |
| `--follow-redirect` | Follow all redirects |
| `--no-redirect` | Skip all redirects, test input target directly |
| `-r`, `--random-agent` | Use a random User-Agent string |
| `--googlebot` | Use Google bot User-Agent |
| `--user-agent <ua>` | Custom User-Agent |
| `-v` | Verbose output |
| `--batch` | Never pause between sites in list scan |
| `--clear-result` | Delete all scan results |
| `--version` | Show version and exit |

## Common Commands

```bash
# Detect CMS and enumerate
cmseek -u http://example.com

# Follow redirects (required for most HTTPS sites)
cmseek -u http://example.com --follow-redirect

# Multiple targets from file
cmseek -l targets.txt --follow-redirect

# Bypass basic WAF User-Agent filtering
cmseek -u http://example.com --random-agent --follow-redirect

# Verbose mode
cmseek -u http://example.com -v
```

## Notes & Tips

1. cmseek covers 180+ CMS types — use it first when you don't know the target CMS, then pivot to specialized tools.
2. Results are saved to `Result/<domain>/cms.json` — review it for version, detected users, and vulnerability data.
3. If detection fails, inspect headers manually: `curl -I http://example.com` often reveals CMS through `X-Powered-By`, cookies, or generator meta tags.
4. For WordPress targets: cmseek confirms the CMS; then use wpscan for plugin/theme/user enumeration and CVE detection.
5. Detected version + nuclei CVE templates is a powerful combination: `nuclei -t http/cves/ -u http://example.com` after cmseek identifies the CMS.

---

## Official References

- [CMSeeK (GitHub)](https://github.com/Tuhinshubhra/CMSeeK)
- [Kali cmseek](https://www.kali.org/tools/cmseek/)
