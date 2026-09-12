# ncrack

- **Category**: Password Attacks / Network Authentication Cracking
- **Risk Level**: 🔴 High

---

## Description

High-speed network authentication cracking tool from the Nmap project. Designed for large-scale network auditing, ncrack uses a modular architecture with protocol-specific modules and a dynamic engine that adapts timing based on network feedback. Supports SSH, RDP, FTP, Telnet, HTTP(S), POP3(S), IMAP, SMB, VNC, SIP, Redis, PostgreSQL, MSSQL, MySQL, MongoDB, Cassandra, WinRM, OWA, and DICOM.

## Installation

```bash
sudo apt install ncrack
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-U <file>` | Username list file |
| `-P <file>` | Password list file |
| `--user <user>` | Comma-separated username list |
| `--pass <pass>` | Comma-separated password list |
| `-T <0-5>` | Set timing template (higher is faster) |
| `-g <opts>` | Options applied to every service globally |
| `-f` | Quit cracking service after first credential found |
| `-v` | Increase verbosity level (use twice or more for greater effect) |
| `-oN <file>` | Output scan in normal format to the given filename |
| `-oX <file>` | Output scan in XML format to the given filename |
| `--resume <file>` | Resume a previously saved session |
| `-iL <file>` | Input from list of hosts/networks |
| `--pairwise` | Choose usernames and passwords in pairs |

### Service Syntax

```
<service>://<host>:<port>
```

Supported service names: `ssh`, `rdp`, `ftp`, `telnet`, `http`, `https`, `pop3`, `pop3s`, `imap`, `smb`, `vnc`, `sip`, `redis`, `psql`, `mssql`, `mysql`, `mongodb`, `cassandra`, `winrm`, `owa`, `dicom`.

## Common Commands

```bash
# SSH brute-force with wordlists
ncrack -U users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# RDP brute-force (single user, conservative timing)
ncrack --user administrator -P wordlist.txt rdp://192.168.1.100 -T 3

# Multi-service cracking from Nmap XML output
nmap -sV -oX scan.xml 192.168.1.0/24
ncrack -iX scan.xml -U users.txt -P wordlist.txt

# Multiple targets and services in one command
ncrack -U users.txt -P wordlist.txt ssh://192.168.1.100 rdp://192.168.1.101 ftp://192.168.1.102

# Stop after first credential found per service, save results
ncrack --user root -P wordlist.txt ssh://192.168.1.100 -f -oN /tmp/ncrack_results.txt

# Resume an interrupted session
ncrack --resume /tmp/ncrack_results.txt

# Fine-tune connection parameters globally
ncrack -U users.txt -P wordlist.txt ssh://192.168.1.100 -g cl=5,at=3,cd=500ms
# cl=max concurrent logins, at=authentication tries per connection, cd=connection delay
```

## Notes & Tips

1. Service detection: use `nmap -sV` first to identify running services and feed the XML output directly to ncrack with `-iX`.
2. RDP brute-forcing is slow by design due to the protocol handshake — keep timing at `-T 3` or lower to avoid connection drops.
3. Use `-f` to stop after the first valid credential per service — this prevents unnecessary load and reduces detection risk.
4. Global options via `-g` allow fine-grained control: `cl` (connection limit), `at` (auth tries per connection), `cd` (connection delay), `to` (timeout).
5. Compare with `hydra` and `medusa`: ncrack excels at large-scale multi-host scanning with adaptive timing; hydra has broader protocol coverage; medusa offers modular design.

---

## Official References

- [Ncrack — Nmap Project](https://nmap.org/ncrack/)
- [ncrack (GitHub)](https://github.com/nmap/ncrack)
- [Kali ncrack](https://www.kali.org/tools/ncrack/)
