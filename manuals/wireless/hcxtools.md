# hcxtools

- **Category**: Wireless / Capture Processing
- **Risk Level**: 🟡 Medium

---

## Description

A suite of utilities for converting and processing wireless network capture files. Converts captures from hcxdumptool, airodump-ng, and other wireless tools into hashcat-compatible formats for offline WPA/WPA2 cracking. The primary tool is `hcxpcapngtool`, which extracts PMKID and EAPOL handshake hashes into the unified hashcat mode 22000 format. PMKID attacks do not require a connected client — the PMKID is present in EAPOL association frames sent by the AP.

## Installation

```bash
sudo apt install hcxtools
```

## Parameter Reference

### hcxpcapngtool (main conversion tool)

| Parameter | Description |
|-----------|-------------|
| `-o <file>` | Output WPA-PBKDF2-PMKID+EAPOL hash file |
| `-E <file>` | Output wordlist (autohex enabled on non-ASCII characters) |
| `--csv=<file>` | Output access point information in CSV format (delimiter: tabulator) |
| `<input.pcapng>` | Input capture file |

### hcxhashtool (hash filtering tool)

| Parameter | Description |
|-----------|-------------|
| `-i <file>` | Input hashcat 22000 file |
| `-o <file>` | Output WPA-PBKDF2-PMKID+EAPOL hash file |

## Common Commands

```bash
# Convert pcapng capture to hashcat 22000 format (PMKID + EAPOL)
hcxpcapngtool -o hash.hc22000 capture.pcapng

# Also extract ESSID list during conversion
hcxpcapngtool -o hash.hc22000 -E essids.txt capture.pcapng

# Output AP information in CSV format
hcxpcapngtool -o hash.hc22000 --csv=apinfo.csv capture.pcapng

# Crack the converted hash with hashcat (mode 22000)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# Full pipeline: capture → convert → crack
# 1. Capture (with hcxdumptool or airodump-ng):
hcxdumptool -i wlan0mon -o capture.pcapng
# 2. Convert:
hcxpcapngtool -o hash.hc22000 capture.pcapng
# 3. Crack:
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

## Notes & Tips

1. hcxtools is used AFTER capturing — it converts raw captures to crackable format; it does not capture itself.
2. Hashcat mode 22000 combines both PMKID and EAPOL hashes — always use this over legacy modes 2500 and 16800.
3. PMKID attacks do not require a connected client — the PMKID is extracted from EAPOL association frames broadcast by the AP.
4. Filter to target networks with `hcxhashtool` before cracking to reduce hash list size and improve speed.
5. For best results: capture with hcxdumptool → convert with hcxpcapngtool → crack with hashcat -m 22000.

---

## Official References

- [hcxtools (GitHub)](https://github.com/ZerBea/hcxtools)
- [Kali hcxtools](https://www.kali.org/tools/hcxtools/)
