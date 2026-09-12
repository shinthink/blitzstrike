# crackle

- **Category**: Wireless / BLE Cryptanalysis
- **Risk Level**: 🔴 High

---

## Description

BLE legacy pairing key recovery tool. It attacks weak Bluetooth Low Energy pairing captures to recover keys and decrypt traffic when the pairing method is vulnerable.

## Installation

```bash
apt-get update && apt-get install -y crackle
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-i <pcap>` | Input BLE pairing capture |
| `-o <file>` | Output decrypted capture or key material |
| `-l <ltk>` | Long-term key (128-bit hex) for decryption mode |

## Common Commands

```bash
# Recover BLE legacy pairing key from capture
crackle -i capture.pcap -o /tmp/ble_decrypted.pcap

# Decrypt traffic using a known Long-term Key
crackle -i capture.pcap -o /tmp/ble_decrypted.pcap -l 81b06facd90fe7a6e9bbd9cee59736a7
```

## Notes & Tips

1. Requires a BLE pairing capture containing the needed pairing exchange.
2. Works only against vulnerable legacy pairing scenarios; modern LE Secure Connections are not the same target.
3. Treat decrypted traffic as sensitive evidence.

---

## Official References

- [crackle GitHub](https://github.com/mikeryan/crackle)
- [Kali crackle](https://www.kali.org/tools/crackle/)

