# SIPVicious

- **Category**: VoIP-ICS / VoIP SIP Assessment
- **Risk Level**: 🟡 Medium

---

## Description

SIP auditing toolkit for discovering SIP services, enumerating extensions, and testing SIP authentication in authorized VoIP assessments.

## Installation

```bash
apt-get update && apt-get install -y sipvicious
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `svmap` | Discover SIP hosts |
| `svwar` | Enumerate extensions |
| `svcrack` | Test SIP credentials |
| `-p <port>` | Destination port or port ranges (e.g., `5060,5061,8000-8100`) |
| `-m <method>` | Specify the request method (default: OPTIONS) |
| `-d <wordlist>` | Dictionary file for extension/password enumeration (`svwar`/`svcrack`) |
| `-D` | Enable default extensions/passwords scan (`svwar`/`svcrack`) |
| `-e <range>` | Specify an extension or range |
| `-u <extension>` | Target SIP extension to brute-force |
| `-s <name>` | Save session (allows resume and export) |
| `--resume <name>` | Resume a previous scan |
| `--randomize` | Randomize scanning order |
| `-6` | Scan IPv6 address |
| `-t <seconds>` | Timeout / throttle speed (e.g., 0.5) |
| `-c` | Enable compact mode (smaller packets) |
| `-v` | Increase verbosity |

## Common Commands

```bash
# Discover SIP hosts
svmap <cidr> -p 5060

# Enumerate extensions with dictionary
svwar -d <extensions.txt> <sip-host>

# Test known extension passwords with approval
svcrack -u <extension> -d <wordlist> <sip-host>
```

## Notes & Tips

1. SIP enumeration and password testing can trigger account lockouts or alerts; confirm VoIP scope and limits.
2. Validate discovered extensions by response behavior; SIP servers often return misleading status codes.
3. Use packet captures to preserve evidence for SIP findings.

---

## Official References

- [SIPVicious GitHub](https://github.com/EnableSecurity/sipvicious)
- [Kali sipvicious](https://www.kali.org/tools/sipvicious/)

