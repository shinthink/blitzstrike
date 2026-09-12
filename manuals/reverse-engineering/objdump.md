# objdump

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Displays detailed information about object files, executables, and shared libraries. Used for examining section headers, disassembling specific sections (e.g., `.plt` to see imported library functions), and extracting binary metadata.

## Installation

```bash
apt install binutils
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d` | Disassemble executable sections (`.text`) |
| `-d -j .plt` | Disassemble only the PLT section (imported function stubs) |
| `-p` | Print object file private headers (ELF program headers, dynamic section) |
| `-x` | Print all headers (equivalent to `-a -f -h -p -r -t`) |
| `-T` | Print dynamic symbol table |
| `-t` | Print regular symbol table |
| `-R` | Print dynamic relocation entries |
| `-s` | Full contents of all sections (hex dump of data sections) |
| `-S` | Interleave source code with disassembly (debug info required) |
| `-C` | Demangle C++ symbol names |
| `-D`, `--disassemble-all` | Disassemble all sections (not just code) |
| `--visualize-jumps` | Visual jump flow arrows |

## Common Commands

```bash
# Disassemble PLT to list all imported library functions
objdump -d -j .plt /usr/bin/target | grep '@plt>:' | awk '{print $2}'

# Check dynamic library dependencies (safer than ldd for untrusted binaries)
objdump -p /usr/bin/target | grep NEEDED

# Check for writable sections (GOT overwrite opportunity)
objdump -h /usr/bin/target | grep -E 'W|DATA'

# List all dynamic symbols
objdump -T /usr/bin/target | grep 'DF .text'

# Examine ELF program headers for stack/heap permissions
objdump -p /usr/bin/target | grep -A1 'GNU_STACK\|GNU_RELRO'

# Extract the .rodata section (hardcoded strings, config data)
objdump -s -j .rodata /usr/bin/target | head -40
```

## Notes & Tips

1. `objdump -p` is the safe alternative to `ldd` for examining library dependencies of untrusted binaries — it reads the ELF header without executing the binary.
2. PLT (Procedure Linkage Table) analysis reveals which libc functions the binary calls — look for `system`, `exec*`, `popen`, `strcpy`, `gets`.
3. `GNU_STACK` with `RWE` permissions indicates an executable stack — a strong exploitation indicator.
4. `GNU_RELRO` set to `Partial RELRO` means the GOT (Global Offset Table) may be writable — enabling GOT overwrite attacks.

---

## Official References

- [GNU Binutils — objdump](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [objdump(1) — Linux manual page](https://man7.org/linux/man-pages/man1/objdump.1.html)
