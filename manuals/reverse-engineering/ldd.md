# ldd

- **Category**: Reverse Engineering / Binary & Library Analysis
- **Risk Level**: 🟢 Low

---

## Description

Prints shared library dependencies of an executable or shared library. Used for identifying library hijacking opportunities — if the binary loads a library from a writable path, an attacker can replace it with a malicious version.

## Installation

```bash
apt install libc-bin
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-v` | Verbose — print all version information |
| `-u` | Print unused direct dependencies (libraries linked but not actually needed) |
| `-d` | Perform data relocation and report missing functions |
| `-r` | Perform data and function relocation and report missing objects |

## Common Commands

```bash
# Check library dependencies of a SUID binary (privesc analysis)
ldd /usr/bin/passwd

# Check a custom application for writable library paths
ldd /opt/custom_app/bin/app | grep -v '^/'  # libraries NOT resolved to absolute paths

# Verbose: show version requirements
ldd -v /usr/bin/sudo

# Check for missing objects (broken linking)
ldd -r /usr/bin/target

# Check libraries loaded by a shared library itself
ldd /lib/x86_64-linux-gnu/libssl.so
```

## Notes & Tips

1. A library shown without an absolute path (e.g., `libfoo.so => not found`) means the dynamic linker will search `LD_LIBRARY_PATH` — this is a hijacking opportunity.
2. `ldd` may execute the binary under the dynamic linker to resolve dependencies. For untrusted binaries, use `objdump -p <binary> | grep NEEDED` or `readelf -d <binary> | grep NEEDED` instead as a safer alternative.
3. Library hijacking requires a writable directory in the search path or the ability to set `LD_LIBRARY_PATH` / `LD_PRELOAD`.
4. For a complete pre-exploit assessment of a SUID binary, use `ldd` (dependencies) + `nm -D` (imported functions) + `readelf -a` (security flags) + `checksec` (exploit mitigations).

---

## Official References

- [ldd(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
