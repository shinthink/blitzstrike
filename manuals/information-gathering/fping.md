# fping

- **Category**: Information Gathering / Host Discovery
- **Risk Level**: 🟢 Low

---

## Description

A fast ICMP ping utility that can probe multiple hosts simultaneously in a round-robin fashion — unlike standard `ping`, which waits for each reply before moving to the next. Ideal for quickly checking which hosts are alive across large IP ranges. Accepts host lists from files or stdin, making it pipeline-friendly for host discovery workflows.

## Installation

```bash
sudo apt install fping
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<host> [host ...]` | One or more target hosts/IPs |
| `-f <file>` | Read targets from file (one per line) |
| `-g <range>` | Generate target list (only if no -f specified) |
| `-a` | Show targets that are alive |
| `-A` | Show targets in IP address format |
| `-c <n>` | Count mode: send N pings to each target |
| `-t <ms>` | Individual target initial timeout (default: 500 ms) |
| `-q` | Quiet (don't show per-target/per-ping results) |
| `-s` | Print final stats |
| `-r <n>` | Number of retries (default: 3) |
| `-b <bytes>` | Ping data size in bytes (useful for MTU testing) |
| `-l` | Loop mode (continuous monitoring) |

## Common Commands

```bash
# Ping a list of IPs from file, show only alive hosts
fping -a -f targets.txt

# Ping entire /24 subnet, show alive hosts only
fping -a -g 192.168.1.0/24

# Generate and ping a range
fping -a -g 192.168.1.1 192.168.1.254

# Fast scan with short timeout
fping -a -t 200 -g 10.0.0.0/24

# Count pings per host and show stats
fping -c 3 -s -g 192.168.1.0/24

# Read from stdin (pipeline)
cat hosts.txt | fping -a

# Suppress errors (cleaner output)
fping -a -q -g 192.168.1.0/24 2>/dev/null
```

## Notes & Tips

1. fping is significantly faster than ping for host discovery across subnets — sends probes to all targets simultaneously.
2. Always add `2>/dev/null` to suppress "ICMP Host Unreachable" messages for cleaner alive-host output.
3. `-t 200` (200ms timeout) is a good balance for LAN scans; increase to 1000ms+ for internet targets.
4. fping output can be piped directly to nmap: `fping -a -g 192.168.1.0/24 2>/dev/null | nmap -iL - -sV`.
5. On networks blocking ICMP, use nmap's `-Pn` or ARP scan instead — ICMP-based discovery may miss firewalled hosts.

---

## Official References

- [fping Official Site](https://fping.org/)
- [Kali fping](https://www.kali.org/tools/fping/)
