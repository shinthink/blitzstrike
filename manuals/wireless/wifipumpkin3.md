# Wifipumpkin3

- **Category**: Wireless / Rogue AP
- **Risk Level**: 🔴 Critical

---

## Description

wifipumpkin3 (wp3) is a powerful rogue access point attack framework written in Python 3. It creates fake wireless access points for man-in-the-middle attacks, credential harvesting, and traffic interception. The framework supports captive portal attacks, DNS spoofing, and SSL stripping via a modular plugin architecture.

Key capabilities:

- Rogue AP creation with configurable ESSID, channel, and security settings
- Captive portal attacks via the `captiveflask` proxy
- Traffic manipulation and inspection via `pumpkinproxy` plugins
- DNS spoofing for phishing and redirection
- Credential sniffing from intercepted traffic
- Deauthentication attack integration for client disassociation
- Interactive console mode (`--pulp`) and scripted command execution (`-x`)

## Installation

```bash
sudo apt install wifipumpkin3

# Or install from source
git clone https://github.com/P0cL4bs/wifipumpkin3.git
cd wifipumpkin3
sudo python3 setup.py install
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <iface>` | Wireless interface for the AP |
| `-iNet <iface>` | Interface for sharing internet to the AP |
| `-s <session>` | Resume a previous session |
| `-p, --pulp <file>` | Script session with a `.pulp` file |
| `-x, --xpulp <cmds>` | Execute commands as a string (`;`-separated) |
| `-m, --wireless-mode <mode>` | Set wireless mode settings |
| `--no-colors` | Disable terminal colors and effects |
| `--rest` | Run the RESTful API |
| `--restport <port>` | Port for the RESTful API (default: 1337) |
| `--username <user>` | Start RESTful API with specified username instead of pulling from wp3.db |
| `--password <pass>` | Start RESTful API with specified password instead of pulling from wp3.db |
| `-iNM <iface>` | Set interface to ignore from NetworkManager |
| `-rNM <iface>` | Remove interface from NetworkManager |

## Common Commands

### Start a Basic Rogue AP

```bash
# Launch wifipumpkin3 on a specific interface (AP config done inside console)
sudo wifipumpkin3 -i wlan0

# Script AP setup with a pulp file
sudo wifipumpkin3 -i wlan0 -p setup.pulp
```

### Interactive Console Mode

```bash
# Start interactive console
sudo wifipumpkin3 -i wlan0

# Inside the console:
# wp3 > set interface wlan0
# wp3 > set essid "FreeWifi"
# wp3 > set proxy captiveflask
# wp3 > start
```

### Scripted Execution

```bash
# Execute commands non-interactively
sudo wifipumpkin3 -i wlan0 -x "set essid TestAP; set proxy pumpkinproxy; start"
```

## Notes & Tips

1. Requires a wireless adapter that supports AP (master) mode; monitor mode alone is not sufficient
2. Run with `sudo` as root privileges are required for AP creation and network configuration
3. The interface must not be managed by NetworkManager; stop it with `sudo systemctl stop NetworkManager` or exclude the interface
4. Captive portal templates can be customized under the `captiveflask` plugin directory
5. For Deauthentication attacks to force clients onto the rogue AP, use a separate tool (e.g., `aireplay-ng`) on a second wireless interface
6. Logs and captured credentials are stored in `~/.config/wifipumpkin3/`
7. Combine with `pumpkinproxy` plugins for JS injection, image replacement, and response modification

---

## Official References

- [wifipumpkin3 (GitHub)](https://github.com/P0cL4bs/wifipumpkin3)
- [Kali Tools - wifipumpkin3](https://www.kali.org/tools/wifipumpkin3/)
