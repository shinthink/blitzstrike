# Volatility 3

- **Category**: Forensics / Memory Forensics
- **Risk Level**: 🟢 Low

---

## Description

The industry-standard memory forensics analysis framework (version 3). Analyzes memory dump files (.dmp/.raw/.vmem) to extract process lists, network connections, registry keys, password hashes, malicious code, and more. Supports Windows/Linux/macOS memory images.

## Installation

```bash
sudo apt install volatility3

# Or install via pip (get the latest version)
pip install volatility3

vol -h
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `vol -f <FILE> <PLUGIN>` | Basic syntax (-f specifies the memory file, followed by plugin name) |
| `-h, --help` | Show help; use `vol <plugin> --help` for plugin-specific options |
| `-c, --config <CONFIG>` | Load configuration from a JSON file |
| `-v, --verbosity` | Increase output verbosity |
| `-q, --quiet` | Remove progress feedback |
| `-l, --log <LOG>` | Log output to a file as well as the console |
| `-o, --output-dir <DIR>` | Directory in which to output any generated files |
| `-r, --renderer <FORMAT>` | Output format: quick, none, csv, pretty, json, jsonl, arrow, parquet |
| `-p, --plugin-dirs <DIRS>` | Semi-colon separated list of paths to find plugins |
| `-s, --symbol-dirs <DIRS>` | Semi-colon separated list of paths to find symbols |
| `--parallelism [{processes,threads,off}]` | Enable parallelism |
| `--clear-cache` | Clear all short-term cached items |
| `--offline` | Do not search online for additional JSON files |
| `--filters <FILTERS>` | List of filters for output (format: `[+-]columnname,pattern[!]`) |
| `--single-location <LOCATION>` | Specify a base location on which to stack |

## Common Commands

```bash
# Command format
vol -f <memory_dump> <plugin>

# Check basic memory image information
vol -f memory.dmp windows.info
vol -f memory.dmp banners.Banners  # Identify OS/kernel banner from memory image
```

### Common Windows Memory Analysis Commands

```bash
# Process list
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree    # Tree view (parent-child relationships)
vol -f memory.dmp windows.psscan    # Scan for terminated processes

# Network connections
vol -f memory.dmp windows.netstat
vol -f memory.dmp windows.netscan

# Command-line history
vol -f memory.dmp windows.cmdline

# File handles
vol -f memory.dmp windows.handles --pid 1234

# Registry
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Password hash extraction
vol -f memory.dmp windows.registry.hashdump    # SAM hashes
vol -f memory.dmp windows.registry.cachedump   # Domain cached credentials
vol -f memory.dmp windows.registry.lsadump     # LSA Secrets

# Malicious code detection
vol -f memory.dmp windows.malfind   # Detect injected code / process hollowing
vol -f memory.dmp windows.vadinfo --pid 1234  # Virtual address descriptor info

# Extract files
vol -f memory.dmp windows.dumpfiles --pid 1234

# DLL list
vol -f memory.dmp windows.dlllist --pid 1234

# Service list
vol -f memory.dmp windows.svclist    # List services from doubly-linked list
vol -f memory.dmp windows.svcscan    # Scan for services (broader coverage)

# Timeline (combine timestamps from all plugins)
vol -f memory.dmp timeliner.Timeliner

# MFT scan (NTFS Master File Table entries from memory)
vol -f memory.dmp windows.mftscan
```

### Common Linux Memory Analysis Commands

```bash
vol -f memory.dmp linux.pslist
vol -f memory.dmp linux.bash         # bash history
vol -f memory.dmp linux.sockstat     # network connections (preferred; linux.netstat may not exist in all versions)
vol -f memory.dmp linux.mountinfo
```

### Creating Memory Dumps

```bash
# Windows (on the target machine)
# Use ProcDump to dump LSASS
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp

# Full memory dump (requires tools like WinPmem or Magnet RAM Capture)

# Linux (requires root)
# Note: /proc/kcore is the live kernel's ELF core; size varies and may not capture full RAM reliably
# Use the LiME (Linux Memory Extractor) kernel module for reliable full RAM dumps:
# git clone https://github.com/504ensicsLabs/LiME
# cd LiME/src && make && insmod lime-*.ko "path=/tmp/memory.raw format=raw"
sudo dd if=/proc/kcore of=/tmp/memory.raw bs=1M 2>/dev/null || true  # Fallback (limited)
```

## Notes & Tips

1. Always identify the OS profile first — use `windows.info` or `banners.Banners` before running analysis plugins.
2. `windows.pslist` only shows active processes; use `windows.psscan` to detect hidden or terminated processes that may indicate rootkit activity.
3. `windows.malfind` detects memory regions with RWX permissions and no backing file — the primary indicator of process injection and shellcode.
4. `windows.registry.hashdump`, `windows.registry.cachedump`, and `windows.registry.lsadump` are the current hash extraction plugins. The short names (`windows.hashdump`, `windows.cachedump`, `windows.lsadump`) are deprecated aliases.
5. For Linux memory analysis, prefer `linux.sockstat` for network connection data — it is available in all Volatility 3 versions.

---

## Official References

- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [Volatility3 (GitHub)](https://github.com/volatilityfoundation/volatility3)
