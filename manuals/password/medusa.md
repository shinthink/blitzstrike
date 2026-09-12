# Medusa

- **Category**: Password Attacks / Online Password Brute-Force
- **Risk Level**: 🔴 High

---

## Description

A parallel multi-protocol password brute-forcing tool, functionally similar to hydra. Fast and supports 20+ protocols. More stable than hydra for certain protocols (such as MSSQL and VNC).

## Installation

```bash
sudo apt install medusa
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-h HOST` | Target host |
| `-H FILE` | File containing target hostnames or IP addresses |
| `-u USER` | Username |
| `-U FILE` | File containing usernames to test |
| `-p PASS` | Password |
| `-P FILE` | File containing passwords to test |
| `-C FILE` | File containing combo entries |
| `-M MODULE` | Name of the module to execute (without the .mod extension) |
| `-m TEXT` | Parameter to pass to the module. Can be passed multiple times (e.g. `-m Param1 -m Param2`) — required for HTTP/web-form, SMB and other modules |
| `-t N` | Total number of logins to be tested concurrently |
| `-T N` | Total number of hosts to be tested concurrently |
| `-L` | Parallelize logins using one username per thread (default processes the entire username list first) |
| `-f` | Stop scanning host after first valid username/password found |
| `-F` | Stop the entire audit after first valid username/password found on **any** host |
| `-n PORT` | Use a non-default TCP port number |
| `-s` | Enable SSL |
| `-O FILE` | File to append log information to |
| `-r N` | Sleep N seconds between retry attempts (default 3) — this is the delay, not the retry count |
| `-R N` | Attempt N retries before giving up (total attempts = N + 1) |
| `-g N` | Give up after trying to connect for N seconds (default 3) |
| `-Z TEXT` | Resume scan based on map of a previous scan |
| `-d` | Dump all known modules |
| `-q` | Display the module's usage information |
| `-b` | Suppress startup banner |
| `-v N` | Verbose level (0–6) |
| `-w N` | Error debug level (0–10) |
| `-e <ns>` | Additional password checks: n=No Password, s=Password=Username |

### Supported Protocols

AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NCP, NNTP, PcAnywhere, POP3, PostgreSQL, RDP, Rexec, Rlogin, RSH, SMB, SMTP, SNMP, SSHv2, SVN, Telnet, VNC, Web-Form

> ⚠️ **Note**: Medusa's module name for SMB is `smbnt`, not `smb`. Use `-M smbnt`.

## Common Commands

```bash
# SSH brute-force
medusa -h 192.168.1.100 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# FTP brute-force
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ftp

# HTTP form brute-force (use web-form module, not http)
medusa -h target.com -u admin -P wordlist.txt -M web-form \
  -m FORM:"POST:/login" \
  -m FORM-DATA:"user=%U&pass=%P" \
  -m DENY-SIGNAL:"Invalid"

# MySQL brute-force
medusa -h 192.168.1.100 -u root -P wordlist.txt -M mysql -t 4

# SMB brute-force
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M smbnt
```

## Notes & Tips

1. medusa is more reliable than hydra for MSSQL and VNC — prefer medusa for these protocols.
2. Always verify the target's account lockout policy before running medusa — use `-r 30` (30 second retry delay) for sensitive environments.
3. Use `-e ns` to test null passwords and the username as the password in every attempt.
4. For large subnet scans, use `-H hostfile.txt` to target multiple hosts simultaneously.
5. medusa's output file (`-O output.txt`) is pipe-separated — parse it with `grep SUCCESS output.txt` to extract successful credentials.

---

## Official References

- [Medusa (GitHub)](https://github.com/jmk-foofus/medusa)
- [Kali medusa Package Tracker](https://pkg.kali.org/pkg/medusa)
