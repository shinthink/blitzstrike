# checksec

- **Category**: Reverse Engineering / Binary Analysis
- **Risk Level**: 🟢 Low

---

## Description

checksec is a bash script (checksec.sh by slimm609) that examines executable binaries and running processes for various security hardening features. It checks for RELRO (Relocation Read-Only), Stack Canary, NX (No-eXecute), PIE (Position Independent Executable), RPATH, RUNPATH, Fortify Source, and other compile-time protections.

This tool is essential during binary analysis and exploit development to quickly determine what mitigations are in place before attempting exploitation. It can also audit kernel security settings and check all running processes at once.

## Installation

```bash
sudo apt install checksec
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--file={file}` | Check security properties of a single binary file |
| `--dir={directory}` | Check all binaries in a directory |
| `--listfile={file}` | Check binaries listed in a text file (one per line) |
| `--proc={name}` | Check a running process by name |
| `--proc-all` | Check all running processes |
| `--proc-libs={pid}` | Check libraries loaded by a process (by PID) |
| `--kernel[=kconfig]` | Check kernel security configuration |
| `--fortify-file={file}` | Check Fortify Source status of an executable |
| `--fortify-proc={pid}` | Check Fortify Source status of a running process |
| `--format={fmt}` | Output format: cli, csv, xml, json |
| `--output={fmt}` | Alias for --format |
| `--extended` | Show extended information |
| `--verbose` | Enable verbose output |
| `--debug` | Enable debug output |
| `--version` | Show version information |
| `--update` / `--upgrade` | Update checksec to the latest version |

## Common Commands

### Scenario 1: Check a Single Binary

```bash
checksec --file=/usr/bin/ssh
```

Displays RELRO, Stack Canary, NX, PIE, RPATH, RUNPATH, Symbols, and Fortify status for the specified binary.

### Scenario 2: Check All Binaries in a Directory

```bash
checksec --dir=/usr/sbin
```

Scans every executable in the directory and reports their security properties.

### Scenario 3: Check All Running Processes

```bash
checksec --proc-all
```

Lists security properties for every currently running process on the system.

### Scenario 4: Check a Specific Process

```bash
checksec --proc=apache2
```

### Scenario 5: Audit Kernel Security Settings

```bash
checksec --kernel
```

Reports kernel-level protections such as ASLR, kernel stack protector, and other hardening options.

### Scenario 6: JSON Output for Scripting

```bash
checksec --file=/usr/bin/passwd --format=json
```

Outputs results in JSON format for integration with other tools or automated pipelines.

### Scenario 7: Check Fortify Source Protection

```bash
checksec --fortify-file=/usr/bin/ping
```

Shows which functions are fortified vs. unfortified in the binary.

## Notes & Tips

1. checksec is read-only and non-invasive — it only inspects binaries and process metadata, making it safe to run on production systems.
2. Use `--format=json` when piping output to other tools like jq for automated analysis.
3. Full RELRO combined with PIE, NX, and Stack Canary indicates a well-hardened binary.
4. Partial RELRO still leaves the GOT writable, which may be exploitable.
5. No PIE means the binary loads at a fixed address, simplifying ROP chain construction.
6. Run `checksec --proc-all` during reconnaissance to identify weak targets on a compromised host.
7. Do not confuse this tool with `pwn checksec` from pwntools — they check similar properties but are entirely different implementations.

---

## Official References

- [checksec GitHub Repository (slimm609)](https://github.com/slimm609/checksec.sh)
- [checksec Kali Tools Page](https://www.kali.org/tools/checksec/)
