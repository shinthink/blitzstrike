# voiphopper

- **Category**: VoIP-ICS / VoIP VLAN Assessment
- **Risk Level**: 🟡 Medium

---

## Description

VoIP VLAN discovery and hopping tool. It can discover Cisco Discovery Protocol, LLDP-MED, and DHCP voice VLAN information to test whether a host can join a voice VLAN.

## Installation

```bash
apt-get update && apt-get install -y voiphopper
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i <iface>` | Network interface |
| `-c <mode>` | CDP mode: `0` = sniff, `1` = spoof |
| `-l` | List available interfaces for CDP sniffing, then exit |
| `-a` | Avaya DHCP option VLAN discovery |
| `-t <mode>` | Alcatel VLAN discovery mode |
| `-v <vlan>` | Voice VLAN ID for VLAN hop |
| `-d <iface>` | Delete the specified VLAN sub-interface by name, then exit (e.g., `-d eth0.200`) |
| `-D` | Spoof MAC on voice sub-interface only |
| `-m <mac>` | Spoof MAC address (impersonate VoIP phone) |

## Common Commands

```bash
# Sniff for CDP voice VLAN advertisements
voiphopper -i <iface> -c 0

# Spoof CDP to discover voice VLAN
voiphopper -i <iface> -c 1

# Avaya DHCP voice VLAN discovery
voiphopper -i <iface> -a

# Attempt voice VLAN access when authorized
voiphopper -i <iface> -v <vlan-id>

# List available interfaces
voiphopper -l
```

## Notes & Tips

1. Requires local network access and an interface connected to the assessed switch port.
2. Voice VLAN hopping can affect network connectivity; confirm maintenance window and scope.
3. Record VLAN IDs, DHCP leases, and switch discovery evidence.

---

## Official References

- [Kali voiphopper](https://www.kali.org/tools/voiphopper/)

