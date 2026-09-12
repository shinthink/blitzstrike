# AutoRecon

- **Category**: Information Gathering / Automated Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

A multi-threaded automated network reconnaissance tool that orchestrates nmap, gobuster, nikto, enum4linux, and dozens of other tools in parallel against each discovered open port. Runs all appropriate enumeration tools automatically based on detected services, saving hours on initial footprinting. Widely used for OSCP, PNPT, and CTF lab environments where comprehensive enumeration of multiple targets is needed.

## Installation

```bash
sudo apt install autorecon
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<targets>` | IP addresses, CIDR ranges, or hostnames |
| `-t <file>` | Read targets from a file |
| `-o <dir>` | Output directory (default: `./results`) |
| `-p <ports>` | Comma-separated list of ports/port ranges to scan |
| `-m <n>` | Maximum number of concurrent scans to run (default: 50) |
| `-mp <n>` | Maximum number of concurrent port scans per target |
| `-c <file>` | Config file path |
| `-g <file>` | Global file path |
| `--tags <tags>` | Tags to determine which plugins should be included |
| `--exclude-tags <tags>` | Tags to determine which plugins should be excluded |
| `--nmap <opts>` | Override the {nmap_extra} variable in scans |
| `--nmap-append <opts>` | Append to the {nmap_extra} variable in scans |
| `--proxychains` | Run scans through proxychains |
| `--single-target` | Only scan a single target at a time |
| `--no-port-dirs` | Don't create port-specific directories |
| `--only-scans-dir` | Only create the "scans" directory for results |
| `--timeout <m>` | Global maximum run time, in **minutes** (not seconds) |
| `--target-timeout <m>` | Maximum time per target, in **minutes** (not seconds) |
| `--heartbeat <s>` | Heartbeat interval for scan status (seconds) |
| `-v` | Verbose output |

## Common Commands

```bash
# Scan a single target (most common usage)
autorecon 192.168.1.10

# Scan multiple targets
autorecon 192.168.1.10 192.168.1.20 10.0.0.5

# Scan with custom output directory
autorecon 192.168.1.10 -o ./my_results

# Scan from a file of targets
autorecon -t targets.txt

# Scan a CIDR range
autorecon 192.168.1.0/24

# Run only safe plugins (no aggressive scans)
autorecon 192.168.1.10 --tags safe

# Limit concurrent scans for slower networks
autorecon 192.168.1.10 -m 10
```

## Notes & Tips

1. AutoRecon creates an organized directory structure under `results/<target>/` with `scans/`, `exploit/`, `loot/`, and `report/` subdirectories.
2. Review `scans/_quick_tcp_nmap.txt` first for a service overview, then check per-port scan outputs.
3. Automatically dispatches gobuster, nikto, enum4linux, smbclient, and service-specific tools based on open ports.
4. Can be slow on live targets — best used in lab/CTF environments where noise is acceptable.
5. Install dependencies if missing: `sudo apt install autorecon` on a fresh Kali.

---

## Official References

- [AutoRecon (GitHub)](https://github.com/AutoRecon/AutoRecon)
- [Kali autorecon](https://www.kali.org/tools/autorecon/)
