# hcitool

- **Category**: Wireless / Bluetooth
- **Risk Level**: 🟢 Low

---

## Description

Configures Bluetooth connections and sends special commands to Bluetooth devices. Used for discovering nearby Bluetooth devices (inquiry scan), reading device information, and checking connection status.

## Installation

```bash
apt install bluez
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `dev` | Display local Bluetooth devices |
| `scan` | Scan for nearby Bluetooth devices (discoverable only) |
| `inq` | Inquire — extended device information including clock offset and class |
| `info <BD_ADDR>` | Get detailed information about a remote device (LMP version, features) |
| `cc <BD_ADDR>` | Create connection to a remote device |
| `dc <BD_ADDR>` | Disconnect from a remote device |
| `name <BD_ADDR>` | Query the remote device name |
| `con` | List active connections |
| `lescan` | Start BLE (Low Energy) scan |
| `leinfo <bdaddr>` | Get LE remote device information |

## Common Commands

```bash
# Check local Bluetooth adapter
hcitool dev

# Scan for discoverable Bluetooth devices
hcitool scan

# Extended inquiry scan (more detail, takes longer)
hcitool inq

# Get detailed info about a discovered device
hcitool info AA:BB:CC:DD:EE:FF

# Check active connections
hcitool con

# Query device name (even if not shown in scan)
hcitool name AA:BB:CC:DD:EE:FF
```

## Notes & Tips

1. `hcitool scan` only finds devices in discoverable mode — many modern devices are not discoverable but will respond to `info` or `name` queries if you know the BD_ADDR.
2. The Bluetooth adapter must be enabled and powered on. Check with `hciconfig`; use `hciconfig hci0 up` to power on.
3. `hcitool` operates on HCI (Host Controller Interface) level — raw Bluetooth commands, not service-level. Use `sdptool` for SDP service discovery, and `gatttool` for BLE GATT operations.
4. For a complete Bluetooth assessment: `hcitool scan` → `hcitool info` per device → `sdptool browse` per device → `gatttool` for BLE devices.

---

## Official References

- [hcitool Debian man page](https://manpages.debian.org/unstable/bluez/hcitool.1.en.html)
