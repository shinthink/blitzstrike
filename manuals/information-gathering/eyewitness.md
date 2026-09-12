# EyeWitness

- **Category**: Information Gathering / Web Service Screenshots
- **Risk Level**: 🟢 Low

---

## Description

Automatically takes screenshots of large numbers of web services and generates an HTML report, helping testers quickly and visually browse all web interfaces of the target and identify interesting login pages, admin panels, and default pages. Extremely efficient for large-scale target reconnaissance.

## Installation

```bash
sudo apt install eyewitness
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-f FILE` | Line-separated file containing URLs to capture |
| `--single URL` | Single URL/host to capture |
| `-x FILE` | Nmap XML or .Nessus file |
| `--web` | Screenshot using Selenium |
| `-d DIR` | Directory name for report output |
| `--threads N` | Number of threads to use while using file based input |
| `--timeout N` | Maximum seconds to wait while requesting a web page (default: 7) |
| `--no-prompt` | Don't prompt to open the report |
| `--prepend-https` | Prepend http:// and https:// to URLs without either |
| `--resolve` | Resolve IP/hostname for targets |
| `--jitter <max>` | Randomize URLs and add random delay between requests |
| `--delay <n>` | Delay in seconds between opening navigator and screenshot |

## Common Commands

```bash
# Screenshot a URL list (most common workflow)
eyewitness -f /tmp/urls.txt --web -d /tmp/eyewitness_output/ --no-prompt

# Single target
eyewitness --single http://target.com --web -d /tmp/

# Automatically prepend protocol prefix
eyewitness -f /tmp/hosts.txt --web --prepend-https -d /tmp/output/

# Multi-threaded acceleration
eyewitness -f /tmp/urls.txt --web --threads 10 -d /tmp/output/

# Use with nmap results (EyeWitness uses -x for nmap XML, not --nmap-xml)
nmap -sV -p 80,443,8080,8443 -oX /tmp/nmap.xml target.com
eyewitness -x /tmp/nmap.xml --web -d /tmp/output/
```

## Notes & Tips

1. EyeWitness requires a desktop/display environment for the screenshot engine; on a headless Kali server use `Xvfb` (virtual framebuffer) or run via Docker with display forwarding.
2. The generated `report.html` is the primary deliverable — sort entries by HTTP status code or title to quickly surface admin panels and login pages.
3. Use `--prepend-https` when the input list contains bare hostnames without a URL scheme.
4. Large URL lists can take a long time; tune `--threads` and `--timeout` to balance speed vs. completeness.
5. Combine with httpx first to filter live hosts before passing to EyeWitness — avoids wasting time screenshotting dead addresses.

---

## Official References

- [EyeWitness GitHub](https://github.com/RedSiege/EyeWitness)
