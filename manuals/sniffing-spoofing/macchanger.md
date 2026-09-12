# macchanger

- **Category**: Sniffing & Spoofing / Anti-Tracking
- **Risk Level**: 🟢 Low

---

## Description

Changes the MAC address of a network interface. Used before ARP scanning, MITM attacks, or wireless reconnaissance to avoid leaving a traceable hardware address in network logs.

## Installation

```bash
apt install macchanger
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-r` | Set a fully random MAC address |
| `-e` | Don't change the vendor bytes |
| `-a` | Set a random vendor MAC of the same device kind (may choose a different OUI of the same type) |
| `-A` | Set a random vendor MAC of any kind |
| `-m <MAC>` | Set a specific MAC address |
| `-p` | Reset to the original permanent MAC address |
| `-s` | Print the MAC address and exit |

## Common Commands

```bash
# Check current MAC address
macchanger -s eth0

# Randomize MAC address
macchanger -r eth0

# Set specific MAC address
macchanger -m 00:11:22:33:44:55 eth0

# Same vendor MAC (less suspicious on managed networks)
macchanger -e eth0

# Restore original MAC
macchanger -p eth0
```

## Notes & Tips

1. The interface must be down before changing the MAC: `ifconfig eth0 down` or `ip link set eth0 down`.
2. Always `macchanger -s` to verify the change before scanning — a failed MAC change may leave the original address.
3. On some wireless adapters and virtual interfaces, MAC address changes may be blocked by the driver. Test before relying on it in an engagement.
4. Pair MAC randomization with TTL modification and user-agent spoofing for comprehensive anti-tracking during reconnaissance.

---

## Official References

- [macchanger GitHub](https://github.com/alobbs/macchanger)
- [Kali Tools — macchanger](https://www.kali.org/tools/macchanger/)
