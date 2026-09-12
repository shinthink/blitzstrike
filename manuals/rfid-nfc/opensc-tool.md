# opensc-tool

- **Category**: RFID/NFC / Smart Card
- **Risk Level**: 🟢 Low

---

## Description

OpenSC utility for listing PC/SC readers and connected smart cards, including ATR information. Use it as the first inventory step for smart-card assessments.

## Installation

```bash
apt-get update && apt-get install -y opensc pcscd
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-l` | List readers |
| `-n` | Show card name |
| `-a` | Show ATR |
| `-r <reader>` | Select reader |
| `--send-apdu <apdu>` | Send APDU; use with caution |

## Common Commands

```bash
# List readers
opensc-tool -l

# Show card ATR
opensc-tool -a

# Show card name
opensc-tool -n
```

## Notes & Tips

1. Start with reader/card inventory before using more intrusive tools.
2. APDU sending should be treated as high caution and coordinated with card owners.
3. Pair with `pkcs15-tool` for certificates and token objects.

---

## Official References

- [OpenSC GitHub](https://github.com/OpenSC/OpenSC)
- [OpenSC Wiki](https://github.com/OpenSC/OpenSC/wiki)

