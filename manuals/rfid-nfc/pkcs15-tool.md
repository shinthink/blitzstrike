# pkcs15-tool

- **Category**: RFID/NFC / Smart Card
- **Risk Level**: 🟢 Low

---

## Description

OpenSC utility for reading PKCS#15 smart-card objects such as certificates, public keys, and token metadata. Use it for authorized smart-card inventory and certificate extraction.

## Installation

```bash
apt-get update && apt-get install -y opensc pcscd
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `--list-certificates` | List certificates |
| `--read-certificate <id>` | Read certificate by ID |
| `--list-keys` | List keys |
| `--dump` | Dump token object information |
| `--reader <reader>` | Select reader |

## Common Commands

```bash
# List certificates
pkcs15-tool --list-certificates

# Read certificate
pkcs15-tool --read-certificate <id> > /tmp/card-cert.der

# Dump token metadata
pkcs15-tool --dump > /tmp/pkcs15-dump.txt
```

## Notes & Tips

1. Reading public certificates is usually low impact, but still requires authorization.
2. Do not attempt PIN-protected private key operations unless explicitly approved.
3. Hash exported certificate files and record reader/card identifiers.

---

## Official References

- [OpenSC GitHub](https://github.com/OpenSC/OpenSC)
- [pkcs15-tool manual](https://www.mankier.com/1/pkcs15-tool)

