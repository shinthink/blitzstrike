# gatttool

- **Category**: Wireless / Bluetooth (BLE)
- **Risk Level**: 🟡 Medium

---

## Description

Reads from and writes to GATT (Generic Attribute Profile) characteristics on BLE (Bluetooth Low Energy) devices. Used to interact with BLE smart devices — sensors, locks, medical devices, fitness trackers — to test whether sensitive characteristics are accessible without authentication.

## Installation

```bash
apt install bluez
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-b <BD_ADDR>` | Remote BLE device address |
| `-t random` | Use random address type (required for many BLE peripherals) |
| `--primary` | List primary services |
| `--characteristics` | List all characteristics for discovered services |
| `--char-read -a <handle>` | Read a characteristic value by handle |
| `--char-write-req -a <handle> -n <hex_value>` | Write to a characteristic with response |
| `--char-write-cmd -a <handle> -n <hex_value>` | Write to a characteristic without response (no acknowledgement) |
| `--listen` | Listen for notifications/indications from a characteristic |

## Common Commands

```bash
# List primary services on a BLE device
gatttool -b AA:BB:CC:DD:EE:FF --primary

# List all characteristics
gatttool -b AA:BB:CC:DD:EE:FF --characteristics

# Read a specific characteristic
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x0025

# Write to a writable characteristic (e.g., send command to a lock)
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0025 -n 01

# Interactive mode for testing multiple characteristics
gatttool -b AA:BB:CC:DD:EE:FF -I
```

## Notes & Tips

1. Many BLE devices require `-t random` for the address type — if `--primary` returns nothing, try adding `-t random`.
2. After discovering a writable characteristic, test whether the device requires authentication: try writing without bonding/pairing first. If it succeeds, the characteristic is unauthenticated.
3. For continuous monitoring of a characteristic (e.g., temperature sensor, heart rate), use `--listen` to receive periodic notifications without polling.
4. BLE L2CAP connections have a ~30m range in ideal conditions. For devices further away, use a directional or high-gain antenna.

---

## Official References

- [gatttool Debian man page](https://manpages.debian.org/unstable/bluez/gatttool.1.en.html)
