# Patator

- **Category**: Password Attacks / Multi-Protocol Brute Force
- **Risk Level**: 🔴 High

---

## Description

patator is a modular multi-protocol brute-force and testing framework. It supports modules for SSH, FTP, SMTP, HTTP, SMB, RDP, databases, SNMP, and many other services. Use it when hydra or medusa do not support the exact protocol behavior needed, or when you need flexible filtering and module-specific controls.

## Installation

```bash
sudo apt install patator
patator --help
```

## Parameter Reference

| Parameter | Description |
|---------------------|-------------|
| `patator <module>` | Run a module, such as `ssh_login`, `ftp_login`, `http_fuzz`, `smb_login` |
| `host=<host>` | Target host |
| `user=FILE0` | Use first file as username list |
| `password=FILE1` | Use second file as password list |
| `0=<file>` | File mapped to `FILE0` |
| `1=<file>` | File mapped to `FILE1` |
| `-x ignore:<cond>` | Ignore results matching a condition |
| `-x quit:<cond>` | Stop on a matching condition |
| `-t <n>` | Threads |

## Common Commands

```bash
# SSH brute-force
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'

# FTP brute-force
patator ftp_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:code=530

# SMB brute-force
patator smb_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt

# HTTP form fuzzing
patator http_fuzz url=http://target.com/login method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt -x ignore:fgrep='Invalid'

# Stop after the first positive match
patator ssh_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x quit:fgrep!='Authentication failed'
```

## Notes & Tips

1. Always confirm account lockout policy before online brute-force or spraying.
2. Run `patator <module> --help` because each module has different parameters and filters.
3. Use `-x ignore` to hide failures and make successful attempts obvious.
4. Prefer password spraying over brute-force in AD environments; use `kerbrute` or `netexec` when appropriate.
5. Patator is flexible but easy to misconfigure; test against one known-valid credential first when possible.

---

## Official References

- [patator GitHub](https://github.com/lanjelot/patator)
- [Kali patator](https://www.kali.org/tools/patator/)
