# Binwalk

- **Category**: Reverse Engineering / Firmware Analysis
- **Risk Level**: 🟡 Medium

---

## Description

binwalk is a firmware analysis tool that scans binary files for embedded file signatures, compressed archives, executable code, and file system images. It can automatically extract discovered components, perform entropy analysis to identify encrypted or compressed regions, and recursively unpack nested firmware layers. Essential for IoT and embedded device security assessments.

## Installation

```bash
sudo apt install binwalk

# binwalk v3 is a Rust rewrite available from the project's GitHub repository
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-B, --signature` | Scan for file signatures (default mode) |
| `-E, --entropy` | Calculate file entropy |
| `-A, --opcodes` | Scan for executable opcode signatures |
| `-e, --extract` | Automatically extract known file types |
| `-M, --matryoshka` | Recursively scan extracted files |
| `-d, --depth=<n>` | Limit matryoshka recursion depth (default: 8 levels deep) |
| `-D, --dd=<type:ext:cmd>` | Extract specified type signatures |
| `-C, --directory=<dir>` | Extract files/folders to a custom directory (default: cwd) |
| `-j, --size=<n>` | Limit extracted file size |
| `-o, --offset=<n>` | Start scan at this file offset |
| `-t, --term` | Format output to fit the terminal window |
| `-l, --length=<n>` | Number of bytes to scan |
| `-R, --raw=<str>` | Scan target file(s) for the specified sequence of bytes |
| `-q, --quiet` | Suppress output |
| `-Y`, `--disasm` | Identify CPU architecture using capstone disassembler |

## Common Commands

### Scenario 1: Signature scan

```bash
# Scan firmware for known file signatures
binwalk firmware.bin

# Scan with terminal-formatted output
binwalk -t firmware.bin
```

### Scenario 2: Extract embedded files

```bash
# Extract all identified files
binwalk -e firmware.bin

# Recursive extraction (matryoshka mode)
binwalk -eM firmware.bin

# Extract to specific directory
binwalk -e -C /tmp/fw_extracted firmware.bin
```

### Scenario 3: Entropy analysis

```bash
# Generate entropy plot (identifies encrypted/compressed regions)
binwalk -E firmware.bin

# High entropy = encrypted/compressed; low entropy = plaintext/padding
```

### Scenario 4: Opcode analysis

```bash
# Scan for CPU architecture signatures
binwalk -A firmware.bin

# Helps identify target architecture (ARM, MIPS, x86)
```

### Scenario 5: Custom extraction rules

```bash
# Extract only specific file types
binwalk -D 'png image:png' firmware.bin
binwalk -D 'gzip compressed:gz:gunzip {}' firmware.bin

# Extract raw bytes by hex pattern
binwalk -R '\x89PNG' firmware.bin
```

## Notes & Tips

1. Extracted files are placed in a `_<filename>.extracted/` directory by default
2. Matryoshka mode (`-M`) combined with `-e` handles nested firmware layers (SquashFS inside LZMA inside UBI)
3. Entropy analysis helps distinguish encrypted regions (near-uniform high entropy) from compressed ones (high but variable entropy)
4. For large firmware images, use `-l` to limit scan length for faster initial analysis
5. binwalk v3 is a Rust rewrite available from the project's GitHub repository

---

## Official References

- [binwalk (GitHub)](https://github.com/ReFirmLabs/binwalk)
- [binwalk — Kali Tools](https://www.kali.org/tools/binwalk/)
