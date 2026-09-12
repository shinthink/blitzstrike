# wifite

- **Category**: Wireless / Automated Attacks
- **Risk Level**: 🔴 High

---

## Description

Wifite is an automated wireless network attack tool that integrates the functionality of the aircrack-ng suite, reaver, hashcat, and other tools. It can automatically scan networks, select targets, execute attacks (WEP, WPA/WPA2 handshake, WPS PIN, PMKID), and attempt to crack captured keys. Ideal for rapid assessment scenarios — a single command completes the full attack workflow.

## Installation

```bash
sudo apt install wifite

# Install the latest version from GitHub (wifite2)
git clone https://github.com/derv82/wifite2.git
cd wifite2
sudo pip3 install .  # setup.py install is deprecated; use pip instead

# Dependency tools (recommended to install all)
# Note: pyrit is largely unmaintained; hcxdumptool + hcxtools are the key additions
sudo apt install aircrack-ng reaver bully hashcat hcxdumptool hcxtools
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i <interface>` | Wireless interface to use (default: ask) |
| `-c <channel>` | Wireless channel to scan |
| `--kill` | Kill processes that conflict with Airmon/Airodump (default: off) |
| `--wep` | Show only WEP-encrypted networks |
| `--wpa` | Show only WPA/WPA2-encrypted networks (may include WPS) |
| `--wps` | Show only WPS-enabled networks |
| `--wps-only` | Only use WPS PIN and Pixie-Dust attacks (default: off) |
| `--pmkid` | Only use PMKID capture, avoids other WPS and WPA attacks (default: off) |
| `--no-pmkid` | Don't use PMKID capture (default: off) |
| `--dict <file>` | File containing passwords for cracking |
| `--nodeauths` | Passive mode: never deauthenticates clients (default: deauth targets) |
| `--ignore-locks` | Do not stop WPS PIN attack if AP becomes locked (default: stop) |
| `--infinite` | Enable infinite attack mode (default: off) |
| `-pow <dbm>` | Attacks any targets with at least specified signal strength |
| `-first <n>` | Attack the first N targets |
| `--clients-only` | Only show targets that have associated clients (default: off) |
| `-ic, --ignore-cracked` | Hides previously-cracked targets (default: off) |
| `-mac, --random-mac` | Randomize wireless card MAC address (default: off) |

## Common Commands

### Scenario 1: Fully Automatic Attack (Simplest)

```bash
# Fully automatic mode: auto-selects interface, scans, and attacks all visible networks
sudo wifite

# Start after killing interfering processes
sudo wifite --kill

# Specify network adapter
sudo wifite -i wlan0
```

### Scenario 2: Target Filtering

```bash
# Only attack targets with minimum signal strength
sudo wifite -pow -50 --kill

# Only attack targets with connected clients
sudo wifite --clients-only --kill

# Specify channel (reduces scan time)
sudo wifite -c 6 --kill

# Attack only the first target found
sudo wifite -first 1 --kill
```

### Scenario 3: Specify Attack Type

```bash
# WPS attacks only (includes Pixie Dust)
sudo wifite --wps-only --kill

# Capture WPA handshakes only (no cracking)
sudo wifite --wpa --skip-crack --kill

# Use PMKID attack (no need to wait for a client)
sudo wifite --pmkid --kill

# Auto-crack with dictionary after capture
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt --kill
```

### Scenario 4: Offline Cracking of Previously Captured Handshakes

```bash
# Crack saved handshake files using wifite2's built-in --crack flag
wifite --crack --dict /usr/share/wordlists/rockyou.txt

# Or crack directly with aircrack-ng against the default hs/ directory
aircrack-ng -w /usr/share/wordlists/rockyou.txt ./hs/*.cap

# Handshake files are saved by default in the ./hs/ directory
ls ./hs/*.cap
```

### Scenario 5: MAC Randomization (Stealth)

```bash
# Randomize MAC address (reduces traceability risk)
sudo wifite --random-mac --kill
```

## Notes & Tips

1. wifite automatically switches to monitor mode; no manual `airmon-ng` is needed
2. Handshake packets are saved by default to the `hs/` folder in the working directory
3. The `--kill` parameter will disconnect all Wi-Fi connections; use with caution if network connectivity is needed
4. Pixie Dust attacks only work against a limited number of vendor APs; reaver/bully is used for general WPS cracking. Use `--wps-only` to focus on WPS/Pixie attacks.
5. Use `--nodeauths` for purely passive monitoring, waiting for handshakes to occur naturally.
6. A good wordlist is recommended; rockyou.txt may need decompression (`gunzip /usr/share/wordlists/rockyou.txt.gz`), though modern Kali 2023+ ships it pre-extracted

---

## Official References

- [Wifite2 (GitHub)](https://github.com/derv82/wifite2)
