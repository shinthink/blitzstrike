# arp-scan

- **Category**: Information Gathering / Internal Network Host Discovery
- **Risk Level**: 🟡 Medium

---

## Description

A fast ARP scanning tool that discovers LAN hosts and retrieves MAC addresses by sending ARP request packets. Also identifies device vendors. Faster than netdiscover, suitable for quick internal network host inventory.

## Installation

```bash
sudo apt install arp-scan
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l` / `--localnet` | Generate addresses from interface configuration |
| `-I IFACE` | Specify network interface |
| `--destaddr MAC` | Set the destination MAC address |
| `-r N` | Number of retries per host |
| `-t MS` | Timeout in milliseconds |
| `--bandwidth BW` | Set outbound bandwidth (default: 256000) |
| `--arpspa IP` | Set the source IPv4 address |

## Common Commands

```bash
# Scan local network segment (most common)
sudo arp-scan -l

# Specify network interface
sudo arp-scan -I eth0 -l

# Scan specified range
sudo arp-scan 192.168.1.0/24

# Scan specific IP list
sudo arp-scan 192.168.1.1 192.168.1.2 192.168.1.100

# Increase speed
sudo arp-scan -l --bandwidth 1000k

# Display vendor information
sudo arp-scan -l  # Automatically queries MAC vendor database by default
```

## Notes & Tips

1. arp-scan requires root privileges (`sudo`) because it sends raw ARP packets at the link layer.
2. Use `-I` to specify the correct interface when the host has multiple network adapters; the default interface may not reach the target subnet.
3. Increase `--bandwidth` (e.g., `1000k` or `10m`) to speed up large scans, but very high rates can overwhelm switches or trigger port security on managed networks.
4. MAC vendor lookup is done against a local OUI database (`/usr/share/arp-scan/ieee-oui.txt`); update it with `sudo get-oui` if vendor info seems stale.
5. arp-scan only works within the same broadcast domain (Layer 2); it cannot discover hosts across routers. Use nmap or masscan for cross-subnet discovery.

---

## Official References

- [arp-scan GitHub](https://github.com/royhills/arp-scan)
- [Kali arp-scan](https://www.kali.org/tools/arp-scan/)
