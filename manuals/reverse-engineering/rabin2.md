# rabin2 (radare2)

- **Category**: Reverse Engineering / Binary Metadata Extraction
- **Risk Level**: 🟡 Medium

---

## Description

A standalone CLI tool from the radare2 framework that extracts metadata, security features, imports, exports, strings, and section information from binary files. Use it as a fast one-shot binary analysis tool without entering the radare2 interactive shell.

## Installation

```bash
apt install radare2
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-I` | Binary info — architecture, bits, canary, pic, nx, crypto, stripped status |
| `-i` | List imports (functions called from external libraries) |
| `-E` | List exports (functions the binary provides) |
| `-s` | List symbols |
| `-z` | List strings found in the data sections |
| `-S` | List sections with permissions and sizes |
| `-l` | List linked libraries |
| `-R` | List relocations |
| `-qq` | Quiet mode — only output the value (for scripting) |
| `-j` | JSON output (for machine parsing) |

## Common Commands

```bash
# Fast security triage (canary, pic, nx check)
rabin2 -I /usr/bin/target

# Scriptable: extract key security features
rabin2 -I -j /usr/bin/target | jq '{arch: .arch, canary: .canary, pic: .pic, nx: .nx, relro: .relro, stripped: .stripped}'

# List imported functions (look for dangerous calls)
rabin2 -i /usr/bin/target | grep -iE "system|exec|popen|strcpy"

# List linked libraries
rabin2 -l /usr/bin/target

# Extract strings
rabin2 -z /usr/bin/target | head -30

# Check all SUID binaries on a system
find / -perm -4000 -type f 2>/dev/null | while read f; do echo "=== $f ===" && rabin2 -I "$f" 2>/dev/null; done
```

## Notes & Tips

1. `rabin2 -I` is the fastest way to get a complete security snapshot of a binary — it reports canary, pic, nx, and relro status in a single command.
2. `radare2` also provides the interactive reverse engineering shell (`r2 /bin/target`) which is excluded from this skill's scope; use only `rabin2` and `r2 -q -c` one-shot commands.
3. For a stripped binary, `rabin2 -I` reports `stripped: true` — expect no symbol information from `-s` or `-i`.
4. JSON output (`-j`) is the preferred format for agent consumption — pipe to `jq` for filtering.

---

## Official References

- [radare2 GitHub](https://github.com/radareorg/radare2)
- [rabin2 Manual](https://book.rada.re/tools/rabin2/intro.html)
