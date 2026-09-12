# xxd

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Creates a hex dump of a file or converts a hex dump back to binary. Used for quick file format identification, inspecting file headers/magic bytes, and determining whether a file is what it claims to be (e.g., an ELF that is actually a Python script bundled with pyinstaller).

## Installation

```bash
apt install xxd
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l <N>` | Limit output to the first N bytes |
| `-s <N>` | Seek N bytes before starting (positive = from start, negative = from end) |
| `-g <N>` | Group bytes in groups of N (default 2) |
| `-c <N>` | Format N bytes per line (default 16) |
| `-p` | Plain hex dump (no addresses, no ASCII column; same as `-ps`) |
| `-r` | Reverse — convert hex dump back to binary |
| `-i` | Output as C include file |
| `-b` | Binary digit dump (bit-level output) |
| `-e` | Little-endian hex dump |

## Common Commands

```bash
# Check file header magic bytes (first 128 bytes)
xxd -l 128 /usr/bin/target

# Determine if a file is a script disguised as a binary
xxd /usr/bin/target | head -20

# Check ELF magic (should start with 7f 45 4c 46 = ".ELF")
xxd -l 4 /usr/bin/target

# Read specific offset (e.g., check for embedded config data)
xxd -s 0x1000 -l 256 /usr/bin/target

# Plain hex output for piping
xxd -p suspicious_file | head -5

# Reverse: convert hex dump back to binary
xxd -r hex_dump.txt > reconstructed.bin

# Extract strings from hex dump (alternative to strings tool)
xxd suspicious_file | grep -oP '[a-zA-Z0-9_./]{6,}' | sort -u
```

## Notes & Tips

1. The first 4 bytes of any file are the magic bytes. ELF = `7f 45 4c 46`, PE = `4d 5a`, PNG = `89 50 4e 47`, PDF = `25 50 44 46`.
2. If `file` reports "ELF" but `xxd` output shows Python code or shell script content within the first few kilobytes, the file is likely a pyinstaller/shc-encapsulated script.
3. Use `xxd` on suspicious uploads, firmware blobs, or files without extensions to identify the true format.
4. For scripting, `xxd -p` outputs clean hex without addresses — ideal for piping into `grep` or `sed`.

---

## Official References

- [xxd Debian man page](https://manpages.debian.org/unstable/xxd/xxd.1.en.html)
