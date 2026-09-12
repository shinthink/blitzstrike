# nm

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Lists symbols from object files, executables, and shared libraries. Used to identify imported functions (especially dangerous ones like `system`, `exec`, `strcpy`) and exported symbols — without disassembling the binary.

## Installation

```bash
apt install binutils
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-D` | Display dynamic symbols (from `.dynsym` section) — most useful for shared libraries |
| `-g` | Display only external (global) symbols |
| `-u` | Display only undefined symbols (imported from other libraries) |
| `-A` | Print filename before each symbol |
| `-C` | Demangle C++ symbol names into readable form |
| `-l` | Show source file and line number (debug info required) |
| `--defined-only` | Show only symbols defined in the file (useful for finding exported functions) |
| `-P` | POSIX output format (machine-readable) |
| `-n` | Sort symbols by address (numeric sort) |

## Common Commands

```bash
# Find dangerous imported functions (post-exploitation privesc)
nm -D /usr/bin/target | grep -iE "system|exec|popen|fork|strcpy|gets|sprintf"

# List all imported dynamic symbols
nm -D /usr/bin/target | grep ' U '

# List all exported symbols
nm -D /usr/bin/target | grep ' T '

# Check a shared library's exports
nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' T ' | head -20

# Demangle C++ symbols (for C++ binaries)
nm -C /usr/bin/target | grep ' T '

# Machine-readable output for scripting
nm -D -P /usr/bin/target | awk '{print $1, $2}'
```

## Notes & Tips

1. Symbol type codes: `T`=text/code, `U`=undefined/imported, `W`=weak, `B`/`D`=data, `t`/`d`=local (lowercase = local scope).
2. Stripped binaries have no `.symtab` section — use `nm -D` to read the dynamic symbol table, which is needed for runtime linking and cannot be stripped.
3. If a binary imports `system()` or `popen()`, it may be exploitable for command injection if the arguments can be influenced.
4. Use `nm` alongside `ldd` (library dependencies) and `readelf` (security flags) for a full pre-exploit assessment.

---

## Official References

- [GNU Binutils — nm](https://sourceware.org/binutils/docs/binutils/nm.html)
- [nm(1) — Linux manual page](https://man7.org/linux/man-pages/man1/nm.1.html)
