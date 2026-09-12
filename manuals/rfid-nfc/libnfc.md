# libnfc tools

- **Category**: RFID/NFC / NFC
- **Risk Level**: 🟡 Medium

---

## Description

NFC command-line utilities from the libnfc project. Key binaries include `nfc-list`, `nfc-mfclassic`, `nfc-mfultralight`, `nfc-scan-device`, `nfc-barcode`, `nfc-emulate-forum-tag4`, `nfc-jewel`, `nfc-read-forum-tag3`, and `nfc-relay-picc`. Use them for NFC reader detection, tag identification, and MIFARE Classic read/write workflows with authorized cards.

## Installation

```bash
apt-get update && apt-get install -y libnfc-bin libnfc-examples
```

## Parameter Reference

### nfc-list

Lists connected NFC devices and detected tags. No arguments or `--help` flag — just run it directly.

### nfc-mfclassic

Usage: `nfc-mfclassic f|r|R|w|W a|b u|U<uid> <dump.mfd> [<keys.mfd> [f]]`

| Parameter | Description |
|------|------|
| `f` | Format the card |
| `r` | Read card (key A failures skip sectors) |
| `R` | Read card (key A failures abort) |
| `w` | Write card (key A failures skip sectors) |
| `W` | Write card (key A failures abort) |
| `a` / `b` | Use key A or key B for authentication |
| `u` | Unlocked read/write (no authentication) |
| `U<uid>` | Unlocked with UID specification |
| `<dump.mfd>` | Path to dump file (read output / write input) |
| `<keys.mfd>` | Optional key file |
| `f` (trailing) | Force write even on read failures |

### nfc-mfultralight

Read/write MIFARE Ultralight tags.

### nfc-scan-device

Scan for available NFC devices on the system.

## Common Commands

```bash
# List NFC devices and detected tags
nfc-list

# Scan for NFC devices
nfc-scan-device

# Read MIFARE Classic (key A, unlocked mode)
nfc-mfclassic r a u /tmp/card.mfd

# Read MIFARE Classic with key file
nfc-mfclassic r a u /tmp/card.mfd /tmp/keys.mfd

# Write MIFARE Classic (key A, unlocked mode) — HIGH RISK
nfc-mfclassic w a u /tmp/card.mfd

# Read MIFARE Ultralight
nfc-mfultralight r /tmp/ultralight.mfd
```

## Notes & Tips

1. Do not write card data unless explicitly authorized.
2. Some readers require PC/SC service changes or libnfc configuration.
3. Store card dumps as sensitive evidence and hash them immediately.

---

## Official References

- [libnfc GitHub](https://github.com/nfc-tools/libnfc)
- [libnfc Wiki](https://github.com/nfc-tools/libnfc/wiki)

