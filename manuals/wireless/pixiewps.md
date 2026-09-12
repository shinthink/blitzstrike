# Pixiewps

- **Category**: Wireless / WPS Attacks
- **Risk Level**: 🔴 High

---

## Description

pixiewps is an offline WPS PIN brute force tool that exploits the Pixie Dust vulnerability — a weakness in the random number generation of certain WPS implementations. Instead of brute forcing the PIN online against the AP (which takes hours), pixiewps recovers the PIN offline in seconds using cryptographic parameters extracted during a WPS exchange. Typically used with `reaver -K` or `bully` which automate parameter extraction.

## Installation

```bash
sudo apt install pixiewps
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-e <hex>` | PKE — Enrollee public key |
| `-r <hex>` | PKR — Registrar public key |
| `-s <hex>` | Enrollee hash-1 |
| `-z <hex>` | Enrollee hash-2 |
| `-a <hex>` | Authentication session key |
| `-n <hex>` | Enrollee nonce |
| `-m <hex>` | Registrar nonce |
| `-f` | Bruteforce full range (only mode 3) |
| `-v` | Verbosity level (1-3, default: 3) |

## Common Commands

### Scenario 1: Via reaver (recommended)

```bash
# Reaver with Pixie Dust mode (calls pixiewps automatically)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K -vv
```

### Scenario 2: Via bully

```bash
# Bully with Pixie Dust attack
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3
```

### Scenario 3: Standalone with extracted parameters

```bash
# Use parameters extracted from a WPS exchange
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> \
  -a <AuthKey> -n <E-Nonce> -m <R-Nonce>
```

### Scenario 4: Force mode

```bash
# Try all known Pixie Dust algorithms
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> \
  -a <AuthKey> -n <E-Nonce> -m <R-Nonce> -f
```

## Notes & Tips

1. Pixie Dust works only against APs with weak WPS random number generators — not all APs are vulnerable
2. `reaver -K` is the easiest way to use pixiewps — it extracts parameters and calls pixiewps automatically
3. Success is instant (seconds) unlike online brute force (hours); failure means the AP is not vulnerable
4. Vulnerable chipsets include some Ralink, Broadcom, and Realtek implementations
5. Use `wash -i wlan0mon` to identify WPS-enabled APs before attempting Pixie Dust

---

## Official References

- [pixiewps (GitHub)](https://github.com/wiire-a/pixiewps)
- [pixiewps — Kali Tools](https://www.kali.org/tools/pixiewps/)
