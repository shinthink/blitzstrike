# readelf

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Displays detailed information about ELF (Executable and Linkable Format) files. Unlike `objdump`, readelf is ELF-specific and does not use the BFD library, making it more reliable for examining unusual or malformed ELF binaries.

## Installation

```bash
apt install binutils
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-a` | Print all available information (headers, sections, segments, symbols, relocations, notes) |
| `-h` | ELF file header (architecture, entry point, type) |
| `-l` | Program headers (segment layout, GNU_STACK, GNU_RELRO permissions) |
| `-S` | Section headers (all sections with addresses and flags) |
| `-s` | Symbol table (exported/imported symbols) |
| `-d` | Dynamic section (library dependencies, RUNPATH, RELRO, flags) |
| `-r` | Relocation entries |
| `-n` | Notes section (ABI info, build ID) |
| `-W` | Wide output (don't truncate) |
| `--dyn-syms` | Display dynamic symbol table specifically |

## Common Commands

```bash
# Full security assessment of a binary
readelf -a /usr/bin/target | grep -E "STACK|RELRO|Type:|Machine:|Class:"

# Check executable stack (RWE = exploitable)
readelf -l /usr/bin/target | grep GNU_STACK

# Check RELRO status (Partial = GOT writable)
readelf -d /usr/bin/target | grep -E "RELRO|BIND_NOW"

# Library dependencies (safer than ldd)
readelf -d /usr/bin/target | grep NEEDED

# Check if binary is position-independent (PIE)
readelf -h /usr/bin/target | grep Type:

# Check RUNPATH / RPATH (library hijacking vector)
readelf -d /usr/bin/target | grep -E "RPATH|RUNPATH"

# List all symbols
readelf -s /usr/bin/target
```

## Notes & Tips

1. `readelf -l | grep GNU_STACK` showing `E` (execute) permission means the stack is executable — one of the strongest exploitation indicators.
2. `readelf -d | grep BIND_NOW` is absent → lazy binding enabled → GOT entries resolved on first call, which is exploitable under certain conditions.
3. `DYN (Position-Independent Executable file)` in the ELF header `Type:` means PIE is enabled (harder to exploit with fixed addresses).
4. Use `readelf` instead of `ldd` on untrusted binaries — `readelf` parses the file without executing it.

---

## Official References

- [readelf(1) — Linux manual page](https://man7.org/linux/man-pages/man1/readelf.1.html)
