# airodump-ng

- **Category**: Wireless / Traffic Capture
- **Risk Level**: 🟡 Medium

---

## Description

airodump-ng is the wireless packet capture tool in the aircrack-ng suite. Operating in monitor mode, it displays real-time detailed information about all nearby 802.11 networks (SSID, BSSID, channel, encryption type, client list, etc.) and saves captured packets to .cap files for offline analysis and cracking with tools like aircrack-ng.

## Installation

```bash
sudo apt install aircrack-ng
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-c <channel>` | Lock to the specified channel (1-14 for 2.4GHz, 36+ for 5GHz) |
| `-b <bssid>` | Capture only data from the specified BSSID (MAC address) AP |
| `--bssid <bssid>` | Same as `-b` |
| `-e <essid>` | Capture only the specified SSID network |
| `-w <prefix>` | Save captured data to file (automatically appends .cap/.csv/.kismet.csv suffixes) |
| `--write <prefix>` | Same as `-w` |
| `--output-format <fmt>` | Output format: pcap, ivs, csv, gps, kismet, netxml, logcsv |
| `-a` | Filter unassociated clients (hide clients not connected to any AP) |
| `--band <bands>` | Scan frequency band(s): a=5GHz, b/g=2.4GHz; combine letters for multiple (e.g., abg=both 2.4GHz+5GHz) |
| `--channel <ch>` | Scan specified channel list (comma-separated) |
| `--berlin <secs>` | Seconds before removing a vanished AP from the list (default 120s) |
| `-r <file>` | Read from existing file (offline mode) |
| `--wps` | Show WPS information |
| `--manufacturer` | Attempt to identify device manufacturer |
| `--encrypt <enc>` | Filter by encryption type (OPN, WEP, WPA, WPA2, WPA3) |
| `--update <secs>` | Display update interval (seconds, default 1) |
| `--ignore-negative-one` | Suppress channel -1 warnings |

### Output Field Reference

### AP Section
| Field | Description |
|------|------|
| BSSID | AP MAC address |
| PWR | Signal strength (dBm; closer to 0 = stronger) |
| RXQ | Receive quality percentage over the last 10 seconds |
| Beacons | Number of beacon frames received |
| #Data | Number of data packets captured (or unique IV count for WEP) |
| #/s | Packets per second over last 10 seconds |
| CH | Channel |
| MB | Maximum speed (11=802.11b, 54=802.11g, higher=802.11n/ac) |
| ENC | Encryption type (OPN/WEP/WPA/WPA2/WPA3) |
| CIPHER | Cipher algorithm (TKIP/CCMP/WRAP, etc.) |
| AUTH | Authentication method (PSK/MGT/SAE) |
| ESSID | Network name (SSID) |

### Client Section
| Field | Description |
|------|------|
| BSSID | Associated AP MAC |
| STATION | Client MAC address |
| PWR | Signal strength |
| Rate | Transmission rate |
| Lost | Number of lost data frames over last 10 seconds |
| Packets | Total data packets sent by the client |
| Probe | List of SSIDs probed by the client |

## Common Commands

### Scenario 1: Full-Band Scan

```bash
# Basic scan to view all visible networks
sudo airodump-ng wlan0mon

# Scan the 5GHz band
sudo airodump-ng --band a wlan0mon

# Scan both 2.4GHz and 5GHz simultaneously
sudo airodump-ng --band abg wlan0mon
```

### Scenario 2: Targeted Handshake Capture

```bash
# Lock to target AP and save capture file
# -c: channel, --bssid: target AP, -w: output file prefix
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /tmp/capture wlan0mon

# After capture, the resulting files are:
# /tmp/capture-01.cap  (main packet file)
# /tmp/capture-01.csv  (CSV summary)
# /tmp/capture-01.kismet.csv
# /tmp/capture-01.kismet.netxml
```

### Scenario 3: Filter Unassociated Clients

```bash
# Hide unassociated clients (show only clients connected to an AP)
sudo airodump-ng -a wlan0mon

# Show WPS information (for use with reaver)
sudo airodump-ng --wps wlan0mon
```

### Scenario 4: Display Manufacturer Information

```bash
# Show device manufacturer for APs and clients
sudo airodump-ng --manufacturer wlan0mon
```

### Scenario 5: Offline Analysis

```bash
# Read and analyze an existing cap file
sudo airodump-ng -r /tmp/capture-01.cap
```

## Notes & Tips

1. Capturing a handshake requires waiting for a client to connect, or using aireplay-ng to send Deauth packets to force reconnection
2. The `-w` file prefix is auto-numbered: `capture` → `capture-01.cap`, `capture-02.cap`, etc.
3. `PWR = -1` means the driver does not report signal strength; this does not affect capture
4. Channel hopping causes some packet loss; locking to the target channel improves capture quality
5. `ENC=OPN` means an open network; `WPA2` requires capturing the four-way handshake (EAPOL)
6. Captured .cap files can be opened in Wireshark for analysis

---

## Official References

- [airodump-ng Documentation](https://www.aircrack-ng.org/doku.php?id=airodump-ng)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
