# hping3

- **Category**: Sniffing & Spoofing / Packet Crafting
- **Risk Level**: 🟡 Medium

---

## Description

An active network packet crafting and analysis tool supporting TCP, UDP, ICMP, and raw IP modes. Used for firewall rule testing, port scanning with custom TCP flags, traceroute using various protocols, OS fingerprinting, and DoS simulation. One of the oldest Kali tools — irreplaceable for low-level network probing where nmap's abstraction is insufficient, particularly for testing firewall behavior and bypass techniques.

## Installation

```bash
sudo apt install hping3
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-1` | ICMP mode |
| `-2` | UDP mode |
| (default) | TCP mode |
| `-8` | Scan mode (port range scanning) |
| `-S` | Set SYN flag |
| `-A` | Set ACK flag |
| `-F` | Set FIN flag |
| `-R` | Set RST flag |
| `-p <port>` | Destination port |
| `-s <port>` | Source port |
| `-c <n>` | Packet count |
| `-i u<n>` | Wait interval (uX for X microseconds, e.g., `-i u1000`) |
| `-a <ip>` | Spoof source IP address |
| `--traceroute` | Traceroute mode |
| `-V` | Verbose mode |
| `--flood` | Send packets as fast as possible, don't show replies |
| `-0`, `--rawip` | RAW IP mode |
| `-9`, `--listen` | Listen mode (receive packets matching signature) |

## Common Commands

```bash
# ICMP ping (like ping but with more control)
hping3 -1 192.168.1.10 -c 3

# TCP SYN probe on port 80
hping3 -S -p 80 192.168.1.10 -c 3

# Traceroute using ICMP
hping3 --traceroute -V -1 192.168.1.1

# Traceroute using TCP port 80 (bypasses ICMP filters on firewalls)
hping3 --traceroute -S -p 80 192.168.1.1

# Firewall testing: send ACK to check stateless vs stateful firewall
hping3 -A -p 80 192.168.1.10 -c 3

# Port scan using scan mode (ports 1-1024)
hping3 -8 1-1024 -S 192.168.1.10

# SYN flood simulation (DoS — only on authorized isolated targets)
hping3 -S -p 80 --flood 192.168.1.10

# Spoof source IP address
hping3 -S -p 80 -a 10.0.0.1 192.168.1.10 -c 3
```

## Notes & Tips

1. Use TCP traceroute (`-S -p 80`) to bypass firewalls that block ICMP — reaches further into filtered networks.
2. `--flood` for DoS simulation is high-risk — only use on isolated lab systems with explicit authorization.
3. Source IP spoofing (`-a`) is useful for testing ingress filtering — responses go to the spoofed IP, not Kali.
4. For standard port scanning, nmap is more appropriate; use hping3 when you need precise TCP flag control or timing.
5. The ACK scan (`-A`) is effective for mapping stateless firewalls — an RST reply means the port is reachable past the firewall.

---

## Official References

- [hping3 Debian man page](https://manpages.debian.org/hping3/hping3.8.en.html)
- [Kali hping3](https://www.kali.org/tools/hping3/)
