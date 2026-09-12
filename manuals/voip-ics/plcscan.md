# plcscan

- **Category**: VoIP-ICS / ICS Device Discovery
- **Risk Level**: 🟡 Medium

---

## Description

Industrial control system discovery tool used to identify PLCs and ICS protocols such as Siemens S7 and Modbus. Use only for explicitly authorized OT/ICS scopes.

## Installation

```bash
git clone https://github.com/meeas/plcscan.git
cd plcscan
```

> **⚠️ WARNING**: plcscan is a Python 2 script and is **non-functional on modern Kali** (Python 3). Running it produces a `SyntaxError` due to Python 2 `print` statement syntax. You must either install Python 2 separately, use a Python 2 Docker container, or find a maintained Python 3 fork.

## Parameter Reference

| Parameter | Description |
|------|------|
| `<target>` | Target IP, host:port, or CIDR range |
| `--timeout <seconds>` | Connection timeout in seconds |
| `--hosts-list <file>` | File containing list of hosts to scan |

## Common Commands

```bash
# Discover PLC services on a target
python plcscan.py <target>

# Scan a small authorized range
python plcscan.py <cidr>
```

> **⚠️ Non-functional**: This script requires Python 2 and will fail with `SyntaxError` on Python 3 (the default on modern Kali). See Installation note above.

## Notes & Tips

1. ICS scanning can be operationally sensitive; prefer passive inventory before active probes.
2. Confirm exact script syntax with `--help` because maintained forks differ.
3. Do not fuzz or write to PLCs unless explicitly authorized by OT owners.

---

## Official References

- [plcscan GitHub](https://github.com/meeas/plcscan)

