# airgeddon

- **Category**: Wireless / Automated Auditing
- **Risk Level**: 🔴 High

---

## Description

A comprehensive all-in-one wireless auditing script with a structured menu interface for the complete Wi-Fi attack workflow: monitor mode setup, deauthentication, WPA/WPA2 handshake capture, PMKID attack, evil-twin AP creation, captive portal credential harvesting, and WPS attacks. Automates and orchestrates the aircrack-ng suite and other wireless tools, making it ideal for structured wireless security assessments.

## Installation

```bash
sudo apt install airgeddon
```

## Parameter Reference

airgeddon is entirely menu-driven and does not accept traditional CLI flags. Configuration is controlled via environment variables, which can be set on the command line or persisted in `.airgeddonrc`.

| Parameter | Description |
|-----------|-------------|
| `AIRGEDDON_AUTO_UPDATE` | Enable/disable automatic updates (`true`/`false`) |
| `AIRGEDDON_SKIP_INTRO` | Skip the intro animation (`true`/`false`) |
| `AIRGEDDON_5GHZ_ENABLED` | Enable 5 GHz band support (`true`/`false`) |
| `AIRGEDDON_PLUGINS_ENABLED` | Enable plugin loading (`true`/`false`) |
| `AIRGEDDON_WINDOWS_HANDLING` | Window manager: `xterm` or `tmux` |
| `AIRGEDDON_DEBUG_MODE` | Enable debug output (`true`/`false`) |
| `AIRGEDDON_FORCE_IPTABLES` | Force iptables over nftables (`true`/`false`) |

## Common Commands

```bash
# Launch airgeddon (interactive menu-driven)
airgeddon

# Launch with environment variable overrides
AIRGEDDON_AUTO_UPDATE=false AIRGEDDON_5GHZ_ENABLED=true bash airgeddon

# All operations are menu-driven — typical workflow:
# 1. Select network interface
# 2. Put interface in monitor mode
# 3. Scan for target networks (airodump-ng)
# 4. Select target from the scanned list
# 5. Choose attack type from the menu:
#    - DoS (deauthentication flood)
#    - Handshake/PMKID capture → offline cracking
#    - Evil Twin with captive portal (validates captured password against handshake)
#    - WPS brute force (Reaver or Bully)
#    - WEP attacks
```

## Notes & Tips

1. Requires two wireless interfaces for Evil Twin attacks — one for the rogue AP, one for monitoring/deauthentication.
2. airgeddon automatically checks for missing dependencies on Kali and installs them if needed.
3. The "Evil Twin with captive portal" mode validates captured credentials against the WPA handshake before reporting success — identical to Fluxion's approach.
4. PMKID attacks (no client deauth required) are available in the "Handshake/PMKID" menu — use when no clients are connected.
5. Requires physical wireless hardware with monitor mode and packet injection support — not available in Docker containers.

---

## Official References

- [airgeddon (GitHub)](https://github.com/v1s1t0r1sh3r3/airgeddon)
- [Kali airgeddon](https://www.kali.org/tools/airgeddon/)
