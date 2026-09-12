# Fluxion

- **Category**: Wireless / Social Engineering Attack
- **Risk Level**: 🔴 High

---

## Description

A social engineering framework for wireless networks that creates an evil-twin access point, deauthenticates clients from the legitimate AP, and serves a convincing captive portal page prompting victims to enter the Wi-Fi password. Unlike dictionary attacks, Fluxion does not crack the password — the victim types it. Validates captured passwords against the original WPA handshake before reporting success.

## Installation

```bash
sudo apt install fluxion
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-e <essid>` | Target network ESSID |
| `-b <bssid>` | Target AP MAC address |
| `-c <channel>` | Wireless channel to monitor |
| `-a <attack>` | Attack type (attack directory name; run `fluxion -h` to list available attacks) |
| `-l <language>` | Set language |
| `-d` | Debug mode |
| `-m <multiplexer>` | Multiplexer selection (`tmux` or `xterm`) |
| `-v` | Print version |
| `-k` | Kill wireless connections |
| `-r` | Reload driver |
| `--jammer-interface <iface>` | Define jamming interface |
| `--ratio <ratio>` | Set window size ratio |
| (no parameters) | Launch auto mode with menu-driven setup |

## Common Commands

```bash
# Launch fluxion (interactive menu — most common usage)
fluxion

# Launch targeting a specific ESSID
fluxion -e "TargetNetwork"

# Launch targeting by BSSID and channel
fluxion -b AA:BB:CC:DD:EE:FF -c 6

# Inside the Fluxion menu — typical attack flow:
# 1. Select "Captive Portal" attack
# 2. Scan for target network and select from list
# 3. Capture or load existing WPA handshake
# 4. Select captive portal template (ISP/router-branded page)
# 5. Attack runs: deauths clients → rogue AP → captive portal
# 6. Victim connects to rogue AP and enters Wi-Fi password
# 7. Fluxion validates password against handshake → reports success
```

## Notes & Tips

1. Requires two wireless interfaces: one for the rogue AP, one for monitoring/deauthentication — or a single adapter supporting simultaneous modes.
2. Fluxion validates the captured password against the WPA handshake — only reports success when the password is verified.
3. The captive portal templates include ISP-branded pages (TP-Link, Linksys, Netgear, etc.) — select the one matching the target router model.
4. Dependencies (aircrack-ng, hostapd, dnsmasq, etc.) are pre-installed on Kali.
5. Docker containers cannot provide monitor mode hardware access — wireless tools require SSH to a physical or VM Kali instance.

---

## Official References

- [Fluxion (GitHub)](https://github.com/FluxionNetwork/fluxion)
- [Kali fluxion](https://www.kali.org/tools/fluxion/)
