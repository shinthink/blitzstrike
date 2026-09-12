# p0f

- **Category**: Information Gathering / Passive OS Fingerprinting
- **Risk Level**: 🟢 Low

---

## Description

A purely passive operating system and application fingerprinting tool. Infers the remote host's operating system, browser, ISP, device type, and more by analyzing captured network traffic (without actively sending any packets). Suitable for covert reconnaissance scenarios.

## Installation

```bash
sudo apt install p0f
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i IFACE` | Listen on the specified network interface |
| `-r FILE` | Read offline pcap data from a given file |
| `-o FILE` | Write information to the specified log file |
| `-s SOCKET` | Answer to API queries at a named unix socket |
| `-f FILE` | Fingerprint database file (default: /etc/p0f/p0f.fp) |
| `-u USER` | Switch to the specified unprivileged account and chroot |
| `-p` | Put the listening interface in promiscuous mode |
| `-d` | Fork into background (daemon mode) |
| `-L` | List all available network interfaces and exit |
| `-S <limit>` | Limit number of parallel API connections (default: 20) |
| `-t c,h` | Set connection/host cache age limits (default: 30s,120m) |
| `-m C,H` | Cap the number of active connections/hosts (default: 1000,10000) |

## Common Commands

```bash
# Listen on interface for passive identification
sudo p0f -i eth0

# Analyze a captured pcap file
p0f -r /tmp/capture.pcap

# Listen and write to log
sudo p0f -i eth0 -o /tmp/p0f.log

# API mode (for use by other tools)
sudo p0f -i eth0 -s /tmp/p0f.sock
```

## Notes & Tips

1. p0f sends no packets — it is completely invisible to IDS/IPS and to the target; ideal for covert reconnaissance during red team engagements.
2. Run p0f on the gateway or a network tap to passively fingerprint all hosts communicating on the segment.
3. Fingerprint accuracy depends on traffic volume — low-traffic hosts may yield uncertain results; uptime estimates in the output can help confirm longevity.
4. Use `-r` mode to analyze previously captured pcap files offline — useful when live monitoring is not possible.
5. The API socket (`-s`) allows custom tools and scripts to query p0f results programmatically in real time.

---

## Official References

- [p0f Official Site](https://lcamtuf.coredump.cx/p0f3/)
- [p0f GitHub (unofficial mirror)](https://github.com/p0f/p0f)
