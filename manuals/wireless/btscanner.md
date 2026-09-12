# btscanner

- **Category**: Wireless / Bluetooth Reconnaissance
- **Risk Level**: 🟢 Low

---

## Description

Bluetooth discovery and information gathering tool. It scans nearby Bluetooth devices and can collect names, addresses, classes, and service information for authorized wireless assessments.

## Installation

```bash
apt-get update && apt-get install -y btscanner
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--help` | Show help |
| `--cfg=<file>` | Use a custom configuration file |
| `--no-reset` | Skip resetting the Bluetooth adapter before scanning |

## Common Commands

```bash
# Launch btscanner (ncurses interactive mode)
btscanner

# Launch with a custom configuration file
btscanner --cfg=/etc/btscanner.conf
```

## Notes & Tips

1. btscanner is an ncurses interactive tool; it has no batch/non-interactive mode. Output must be extracted from its config-defined log location.
2. Requires a Bluetooth adapter visible to the Kali environment.
3. Treat discovered device names and addresses as sensitive physical-proximity evidence.
4. Follow up with `hcitool info` and `sdptool browse` for selected devices.

---

## Official References

- [Kali btscanner](https://www.kali.org/tools/btscanner/)

