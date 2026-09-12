# nbtscan

- **Category**: Information Gathering / NetBIOS Enumeration
- **Risk Level**: 🟢 Low

---

## Description

nbtscan enumerates NetBIOS name service information from Windows and Samba hosts. It quickly maps IP addresses to NetBIOS names, logged-in users, MAC addresses, and workgroup/domain names. Use it during internal reconnaissance before deeper SMB enumeration with `enum4linux-ng`, `smbmap`, or `smbclient`.

## Installation

```bash
sudo apt update
sudo apt install nbtscan
nbtscan -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<target>` | Single IP, hostname, or CIDR/range |
| `-r` | Use local port 137 for scans (Win95 boxes compatibility) |
| `-v` | Verbose output |
| `-d` | Dump packets (print whole packet contents) |
| `-e` | Format output in `/etc/hosts` format |
| `-l` | Format output in lmhosts format (cannot be combined with `-v`, `-s`, or `-h`) |
| `-b <bandwidth>` | Output throttling: slow output so it uses no more than `bandwidth` bps |
| `-q` | Suppress banners and error messages |
| `-s <separator>` | Script-friendly output: omit column/record headers, separate fields with `separator` |
| `-h` | Print human-readable names for services (must be used with `-v`) |
| `-m <n>` | Number of retransmits (default 0) |
| `-f <file>` | Take IP addresses to scan from file (`-f -` reads from stdin) |
| `-t <ms>` | Wait timeout in milliseconds (default: 1000) |

## Common Commands

```bash
# Scan a subnet for NetBIOS names
nbtscan 192.168.1.0/24

# Verbose scan of a subnet
nbtscan -v 192.168.1.0/24

# Scan targets from a file
nbtscan -f hosts.txt

# Save results for later SMB enumeration
nbtscan 10.0.0.0/24 | tee /tmp/nbtscan.txt

# Extract IPs with NetBIOS responses
nbtscan 10.0.0.0/24 | awk '/^[0-9]/ {print $1}' > /tmp/smb-hosts.txt
```

## Notes & Tips

1. nbtscan uses UDP/137; firewalls may block it even when SMB/445 is open.
2. Use it as a fast naming/context step before running heavier SMB enumeration.
3. NetBIOS names can reveal host roles such as DCs, file servers, and workstations.
4. For domain users, shares, and policies, follow up with `enum4linux-ng` and `smbmap`.

---

## Official References

- [nbtscan Project](http://www.unixwiz.net/tools/nbtscan.html)
- [Kali nbtscan](https://www.kali.org/tools/nbtscan/)
