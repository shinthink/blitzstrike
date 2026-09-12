# modbus-cli

- **Category**: VoIP-ICS / ICS Protocol Assessment
- **Risk Level**: 🟡 Medium

---

## Description

Command-line Modbus client for reading and writing Modbus registers over TCP or serial (RTU). On Kali, the installed binary is `modbus` (a Python-based tool), not the Ruby `modbus-cli` gem. Use only in authorized ICS/OT assessments; even read operations may be sensitive in fragile environments.

## Installation

```bash
# The 'modbus' binary is available via pip
pip install modbus_cli
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `<device>` | Target device (IP:port for TCP, or serial device path for RTU) |
| `<access>` | Register access specification (e.g., `h@100` for holding register 100) |
| `-r`, `--registers <spec>` | Register specification |
| `-s`, `--slave-id <id>` | Modbus slave/unit ID |
| `-b`, `--baud <rate>` | Baud rate for serial RTU connections |
| `-p`, `--stop-bits <n>` | Stop bits for serial |
| `-P`, `--parity {e,o,n}` | Parity: even, odd, or none |
| `-v`, `--verbose` | Verbose output |
| `-S`, `--silent` | Silent mode |
| `-t`, `--timeout <sec>` | Connection timeout |
| `-B`, `--byte-order {le,be,mixed}` | Byte order: little-endian, big-endian, or mixed |

## Common Commands

```bash
# Read holding register 100 from a TCP device
modbus 192.168.1.100:502 h@100

# Read multiple holding registers with slave ID
modbus -s 1 192.168.1.100:502 h@100 h@101 h@102

# Read with verbose output
modbus -v 192.168.1.100:502 h@0/10

# Read via serial RTU with baud rate and parity
modbus -b 9600 -P n /dev/ttyUSB0 h@100

# Specify byte order
modbus -B be 192.168.1.100:502 h@100
```

## Notes & Tips

1. Do not perform write operations unless explicitly authorized and coordinated with OT owners.
2. Prefer passive identification first; active Modbus reads can affect fragile devices or monitoring.
3. The binary name is `modbus`, not `modbus-cli`.
4. Use `--slave-id` to target specific units on a multi-drop bus.

---

## Official References

- [modbus-cli RubyGems](https://rubygems.org/gems/modbus-cli)
- [modbus-cli GitHub](https://github.com/tallakt/modbus-cli)
