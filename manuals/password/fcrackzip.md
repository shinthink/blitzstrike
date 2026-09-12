# fcrackzip

- **Category**: Password Attacks / Archive Password Cracking
- **Risk Level**: 🟢 Low

---

## Description

A fast ZIP archive password cracker supporting dictionary attacks and brute-force with configurable character sets and length ranges. Validates cracked passwords using unzip (always use `-u` to avoid false positives). For RAR, 7z, and PDF archives use `john` or `hashcat` instead — fcrackzip handles ZIP format only.

## Installation

```bash
sudo apt install fcrackzip
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-u` | Use unzip to validate passwords (prevents false positives — always include) |
| `-D` | Dictionary attack mode |
| `-p <wordlist>` | Wordlist file (used with `-D`) |
| `-b` | Brute-force mode |
| `-c <charset>` | Brute-force charset: `a` (lower), `A` (upper), `1` (digits), `!` (special) |
| `-l <min-max>` | Password length range (e.g., `1-8`) |
| `-v` | Verbose output |

## Common Commands

```bash
# Dictionary attack with rockyou.txt (always use -u)
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt archive.zip

# Brute-force: lowercase letters, length 1-8
fcrackzip -u -b -c a -l 1-8 archive.zip

# Brute-force: lowercase + digits, length 4-6
fcrackzip -u -b -c a1 -l 4-6 archive.zip

# Brute-force all printable chars, length 1-6
fcrackzip -u -b -c aA1! -l 1-6 archive.zip

# For other archive formats — use john or hashcat
# RAR:  rar2john archive.rar > hash.txt && hashcat -m 13000 hash.txt rockyou.txt
# 7z:   7z2john archive.7z > hash.txt && hashcat -m 11600 hash.txt rockyou.txt
# PDF:  pdf2john file.pdf > hash.txt && hashcat -m 10700 hash.txt rockyou.txt
```

## Notes & Tips

1. Always use `-u` — without unzip validation, fcrackzip reports many false positives.
2. Start with rockyou.txt dictionary before brute-force — most CTF and pentest archive passwords are in common wordlists.
3. fcrackzip only handles ZIP format — for RAR, 7z, PDF, use `john --format=...` or `hashcat`.
4. `hashcat -m 17200` (PKZIP Compressed) or `-m 17210` (PKZIP Uncompressed) can also crack ZIPs with GPU acceleration.
5. Very complex passwords are computationally infeasible to brute-force — dictionary attacks with targeted wordlists are almost always more effective.

---

## Official References

- [fcrackzip man page](https://manpages.debian.org/fcrackzip)
- [Kali fcrackzip](https://www.kali.org/tools/fcrackzip/)
