# Netdiscover

- **Category**: Information Gathering / Internal Network Host Discovery
- **Risk Level**: 🟡 Medium

---

## Description

An ARP-based host discovery tool designed for internal network scanning. Rapidly discovers active hosts on a LAN by sending/listening for ARP requests. Faster and more reliable than nmap ping scanning (ARP is not filtered by host firewalls). Supports passive mode (completely silent ARP traffic monitoring). Suitable for host enumeration in the early stages of internal network penetration.

## Installation

```bash
sudo apt install netdiscover
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-r RANGE` | Scan a given range instead of auto scan (e.g., 192.168.6.0/24) |
| `-i IFACE` | Your network device |
| `-p` | Passive mode (listen only, do not send ARP) |
| `-s TIME` | Time to sleep between each ARP request (milliseconds) |
| `-n NODE` | Last IP octet of the source IP used for scanning (range 2–253) |
| `-c COUNT` | Number of times to send each ARP request (retry count) |
| `-l FILE` | Scan the list of ranges contained into the given file |
| `-P` | Print results in parseable format and stop after active scan |
| `-L` | Like -P but continue listening after active scan completes |
| `-N` | Do not print header (only valid when -P or -L is enabled) |
| `-S` | Enable sleep time suppression between each request (hardcore mode) |
| `-f` | Enable fastmode scan, recommended for auto |
| `-d` | Ignore home config files (used for autoscan and fast mode) |
| `-R` | Assume user is root / has required capabilities; skip privilege checks (useful in containers or restricted envs) |
| `-m <file>` | Scan a list of known MACs and host names |
| `-F <filter>` | Customize pcap filter expression |

## Common Commands

```bash
# Requires root privileges
# Scan specified subnet
sudo netdiscover -r 192.168.1.0/24

# Specify network interface
sudo netdiscover -i eth0 -r 192.168.1.0/24

# Passive mode (silently monitor ARP traffic)
sudo netdiscover -p -i eth0

# Fast mode
sudo netdiscover -r 10.0.0.0/24 -f

# Specify packet interval (reduces detection probability)
sudo netdiscover -r 192.168.1.0/24 -s 100
```

## Notes & Tips
1. Requires root privileges
2. Only works on the same network segment (Layer 2); ineffective across routers
3. Passive mode is completely silent, suitable for covert reconnaissance
4. Use in combination with arp-scan as a complement
5. netdiscover has no `-h` flag. To view usage, run `netdiscover --help` — it reports an "Invalid extra argument" / invalid option error but still prints the full usage block.
6. In containers or capability-restricted environments, `-R` skips the root/capability check; pair with `-d` to also ignore home config files for clean autoscan/fast-mode runs.

---

## Official References

- [netdiscover GitHub](https://github.com/netdiscover-scanner/netdiscover)
- [Kali netdiscover](https://www.kali.org/tools/netdiscover/)
