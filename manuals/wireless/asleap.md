# asleap

- **Category**: Wireless / LEAP Cracking
- **Risk Level**: 🟡 Medium

---

## Description

asleap exploits weaknesses in Cisco LEAP (Lightweight Extensible Authentication Protocol) and PPTP (MS-CHAPv2) authentication. It captures LEAP challenge/response exchanges from wireless traffic and performs offline dictionary attacks to recover credentials. The tool can also be used for generic MS-CHAPv2 attacks against PPTP VPN connections.

The toolkit includes two components:

- `asleap` — the main attack tool for cracking LEAP/MS-CHAPv2 credentials
- `genkeys` — a preprocessing utility that generates hash and index files from a wordlist for faster cracking

asleap works with both live wireless capture and saved pcap files.

## Installation

```bash
sudo apt install asleap

# Or build from source
git clone https://github.com/joswr1ght/asleap.git
cd asleap
make
```

## Parameter Reference

### asleap

| Parameter | Description |
|-----------|-------------|
| `-i` | Live capture interface |
| `-r` | Read from a libpcap file |
| `-f` | Dictionary file with NT hashes |
| `-n` | Index file for NT hashes |
| `-W` | Dictionary file (special purpose) |
| `-C` | Challenge value in colon-delimited bytes |
| `-R` | Response value in colon-delimited bytes |
| `-s` | Skip the check to verify authentication was successful |

### genkeys

| Parameter | Description |
|-----------|-------------|
| `-r` | Input dictionary file, one word per line |
| `-f` | Output pass+hash filename |
| `-n` | Output index filename |
| `-h` | Last 2 hash bytes to filter with (optional) |

## Common Commands

### Precompute Hash Tables with genkeys

```bash
# Generate hash and index files from a wordlist
genkeys -r /usr/share/wordlists/rockyou.txt -f hashes.dat -n index.dat
```

### Crack LEAP from a Pcap File

```bash
# Attack captured LEAP authentication using precomputed hashes
asleap -r capture.pcap -f hashes.dat -n index.dat
```

### Crack LEAP from Live Capture

```bash
# Capture and crack LEAP in real time on a wireless interface
asleap -i wlan0mon -f hashes.dat -n index.dat
```

### Direct Dictionary Attack (No Precomputation)

```bash
# Use a wordlist directly without genkeys preprocessing
asleap -r capture.pcap -W /usr/share/wordlists/rockyou.txt
```

### Generic MS-CHAPv2 / PPTP Attack

```bash
# Attack MS-CHAPv2 with known challenge and response
asleap -C <challenge_hex> -R <response_hex> -W /usr/share/wordlists/rockyou.txt
```

### Full Workflow: Capture and Crack

```bash
# Step 1: Precompute hashes
genkeys -r /usr/share/wordlists/rockyou.txt -f hashes.dat -n index.dat

# Step 2: Capture LEAP traffic (on monitor mode interface)
asleap -i wlan0mon -f hashes.dat -n index.dat
```

## Notes & Tips

1. The wireless interface must be in monitor mode for live capture; use `airmon-ng start wlan0` to enable monitor mode
2. Precomputing hashes with `genkeys` significantly speeds up cracking compared to direct wordlist attacks with `-W`
3. LEAP is a deprecated protocol; modern networks should use EAP-TLS or PEAP instead
4. asleap can also target MS-CHAPv2 used in PPTP VPN connections, not just wireless LEAP
5. When specifying challenge (`-C`) and response (`-R`) manually, use hexadecimal format
6. The tool outputs the recovered password to stdout upon successful cracking
7. For large wordlists, the genkeys preprocessing step can take significant time but is a one-time cost

---

## Official References

- [asleap (GitHub)](https://github.com/joswr1ght/asleap)
- [Kali Tools - asleap](https://www.kali.org/tools/asleap/)
