# blueranger

- **Category**: Wireless / Bluetooth Reconnaissance
- **Risk Level**: 🟢 Low

---

## Description

Bluetooth proximity estimation tool that uses signal strength indicators to help locate Bluetooth devices during authorized physical security assessments.

## Installation

```bash
apt-get update && apt-get install -y blueranger
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `<interface>` | Bluetooth interface (positional, e.g., `hci0`) |
| `<bdaddr>` | Target Bluetooth address (positional) |
| `-h` | Help |

## Common Commands

```bash
# Estimate proximity for a target device
blueranger hci0 <BD_ADDR>
```

## Notes & Tips

1. Signal strength is noisy; use results as approximate proximity, not precise distance.
2. Requires local Bluetooth adapter access.
3. Combine with `hcitool scan` and `btscanner` for device inventory.

---

## Official References

- [Kali blueranger](https://www.kali.org/tools/blueranger/)

