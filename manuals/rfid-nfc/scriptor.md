# scriptor

- **Category**: RFID/NFC / Smart Card APDU
- **Risk Level**: 🟡 Medium

---

## Description

Text-mode PC/SC APDU batch runner from `pcsc-tools`. It sends commands to a smart card using a batch file or stdin. Use it only when APDU-level testing is explicitly authorized and the card behavior is understood.

## Installation

```bash
apt-get update && apt-get install -y pcsc-tools
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-r <reader>` | Use the indicated reader; defaults to the first PC/SC reader |
| `-p <protocol>` | Use protocol `T=0` or `T=1`; defaults to `T=0` (values use the `T=N` form, not `T0`/`T1`) |
| `-u` | Use unbuffered stdout |
| `<file>` | Read APDU commands from file instead of stdin |

## Common Commands

```bash
# Run APDU commands from a script file
scriptor script.apdu

# Select a specific reader and protocol
scriptor -r 0 -p T=1 script.apdu
```

## Notes & Tips

1. Malformed APDUs can lock, alter, or destabilize cards. Use read-only scripts first.
2. Preserve the script file and full output as evidence.
3. Command files support APDU lines in `CLA INS P1 P2 Lc [data] [le]` form, `reset`, and comments.
4. Prefer `opensc-tool` and `pkcs15-tool` for inventory before custom APDUs.

---

## Official References

- [Debian scriptor man page](https://manpages.debian.org/testing/pcsc-tools/scriptor.1.en.html)
- [Kali pcsc-tools package tracker](https://pkg.kali.org/pkg/pcsc-tools)
- [pcsc-tools upstream](https://pcsc-tools.apdu.fr/)
