# Brutespray

- **Category**: Password Attacks / Default Credential Testing
- **Risk Level**: 🔴 High

---

## Description

Automatically attempts default credentials on discovered services. Takes scan output from Nmap (GNMAP/XML), Nessus, Nexpose, JSON, and lists, then brute-forces credentials across 30+ protocols in parallel. Identifies service types (SSH, FTP, Telnet, MySQL, PostgreSQL, MSSQL, VNC, etc.) and tests built-in default username/password combinations. Bridges the gap between network scanning and initial access — converts a scan into a credential test in a single command.

## Installation

```bash
sudo apt install brutespray
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-f <file>` | File to parse for targets/services; Supported: Nmap, Nessus, Nexpose, Lists, etc |
| `-u <user>` | Username or username list file |
| `-p <pass>` | Password or password list file |
| `-H <host>` | Direct host targeting (service://host:port format) |
| `-C <file>` | Combo list file (user:pass format) |
| `-t <n>` | Threads per host (default: 10) |
| `-T <n>` | Concurrent hosts (default: 5) |
| `-o <dir>` | Output directory for results (default: `brutespray-output`) |
| `-P` | Print found hosts parsed from the provided host/file arguments (preview targets, no attack) |
| `-S` | List all supported services |
| `-r <n>` | Times to retry after a connection-failed error (default: 3) |
| `-w <duration>` | Timeout for bruteforce attempts, e.g. `5s` (default: 5s) |
| `-q` | Suppress the banner |
| `-s <services>` | Only test these services (comma-separated, e.g., `ssh,ftp`) |

## Common Commands

```bash
# Step 1: Run nmap with service detection and XML output
nmap -sV -oX scan.xml 192.168.1.0/24

# Step 2: Spray default credentials against all discovered services
brutespray -f scan.xml

# Test only SSH and FTP
brutespray -f scan.xml -s ssh,ftp

# Custom credentials
brutespray -f scan.xml -u admin -p admin

# Custom credential lists
brutespray -f scan.xml -u users.txt -p passwords.txt

# Save results to output directory
brutespray -f scan.xml -o ./results

# Increase parallelism
brutespray -f scan.xml -t 5 -T 10

# Increase threads per host
brutespray -f scan.xml -t 20
```

## Notes & Tips

1. Most effective against IoT devices, printers, and misconfigured network services that retain factory default credentials.
2. Pair with masscan for fast port discovery → nmap `-sV -oX` for service detection → brutespray for credential testing.
3. Results are saved in `./result/` (or `-o` path) organized by service type — check for found credentials there.
4. Built-in default lists cover the most common service defaults: admin/admin, root/root, admin/password, etc.
5. Keep `-T` low (5 or fewer) per service to avoid triggering account lockouts or IDS alerts.

---

## Official References

- [brutespray (GitHub)](https://github.com/x90skysn3k/brutespray)
- [Kali brutespray](https://www.kali.org/tools/brutespray/)
