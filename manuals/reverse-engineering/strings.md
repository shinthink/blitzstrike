# strings

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Extracts printable character sequences from binary files. Used to find hardcoded credentials, API keys, URLs, error messages, and file magic bytes embedded in executables, libraries, or firmware images — without reverse engineering.

## Installation

```bash
apt install binutils
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-n <N>` / `--bytes=<N>` | Minimum string length (default 4) |
| `-t <radix>` | Print offset before each string: `o`=octal, `d`=decimal, `x`=hex |
| `-e <encoding>` | Character encoding: `s`=7-bit, `S`=8-bit, `b`=16-bit big-endian, `l`=16-bit little-endian, `B`=32-bit big-endian, `L`=32-bit little-endian |
| `-a` / `--all` | Scan entire file (not just data sections) |
| `-f` | Print filename before each string |
| `-d`, `--data` | Only scan data sections of the file |
| `-s <sep>` | Output separator string |

## Common Commands

```bash
# Search for credentials in a binary
strings /usr/bin/target | grep -iE "passwd|password|api.key|secret|token|jwt"

# Search for URLs and IPs
strings /usr/bin/target | grep -iE "https?://|ftp://|\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b"

# Search for file paths and commands
strings /usr/bin/target | grep -E "^/(etc|usr|tmp|opt|home)/"

# Extract SQL queries embedded in binary
strings /usr/bin/target | grep -iE "(SELECT|INSERT|UPDATE|DELETE) "

# Find all strings >= 8 chars with hex offset (for forensics)
strings -n 8 -t x /usr/bin/target > /tmp/strings_target.txt

# Scan firmware image for interesting artifacts
strings -n 6 firmware.bin | grep -iE "password|root|admin|backdoor|debug"
```

## Notes & Tips

1. Default minimum length is 4 — use `-n 8` or higher to reduce noise when searching for meaningful strings.
2. Strings only scans initialized data sections by default; use `-a` to scan the entire binary (may produce more noise).
3. For packed/obfuscated binaries, strings won't find anything useful — the binary must be unpacked first.
4. Combine with `file` and `xxd` for a complete picture: `file` identifies the format, `xxd` shows the raw header, `strings` finds embedded artifacts.

---

## Official References

- [GNU Binutils — strings](https://sourceware.org/binutils/docs/binutils/strings.html)
- [strings(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
