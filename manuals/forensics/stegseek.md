# Stegseek

- **Category**: Forensics / Steganography Analysis
- **Risk Level**: 🟢 Low

---

## Description

An ultra-fast steganography cracker that brute-forces the passphrase on steghide-encoded files. Supports all steghide-compatible formats: JPEG, BMP, WAV, and AU. Can crack the entire rockyou.txt wordlist (14M passwords) in under 2 seconds on modern hardware — far faster than manual steghide attempts. The first tool to try against suspicious files that may contain steghide-hidden data in CTF and forensics scenarios.

## Installation

```bash
# Not in Kali apt repos; install via .deb from GitHub releases:
wget https://github.com/RickdeJager/stegseek/releases/latest/download/stegseek_0.6-1.deb
dpkg -i stegseek_0.6-1.deb
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-sf, --stegofile <file>` | Target stego file (JPEG, BMP, WAV, AU) |
| `-wl, --wordlist <file>` | Wordlist file for passphrase cracking |
| `-xf, --extractfile <file>` | Extract hidden data to specified output file |
| `--seed` | Brute-force using random seeds (no wordlist; useful for CTF default passphrases) |
| `-t, --threads <n>` | Number of threads to use |
| `-f, --force` | Overwrite existing output files |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Suppress normal output |
| `-c, --continue` | Continue cracking after finding a result |
| `-a, --accessible` | Accessible output (no colors, progress bar) |
| `-s`, `--skipdefault` | Don't add default guesses to wordlist (empty password, filename) |

## Common Commands

```bash
# Install wordlists package first if needed
apt-get install -y wordlists

# Crack steghide passphrase using rockyou.txt
stegseek image.jpg /usr/share/wordlists/rockyou.txt

# Extract hidden data to a specific output file
stegseek image.jpg /usr/share/wordlists/rockyou.txt -xf extracted.txt

# Seed-based brute force (no wordlist — useful for empty/default CTF passphrases)
stegseek --seed image.jpg

# After finding the passphrase, extract manually with steghide
steghide extract -sf image.jpg -p 'foundpassphrase'
```

## Notes & Tips

1. stegseek works on all steghide-compatible formats (JPEG, BMP, WAV, AU) — for other steganography tools (e.g., OpenStego), use stegcracker.
2. Can crack rockyou.txt (14M passwords) in under 2 seconds on modern hardware.
3. If stegseek finds no passphrase in rockyou.txt, try a target-specific wordlist generated with cewl.
4. In CTF scenarios, try `--seed` mode first — many CTF challenges use default or empty passphrases.
5. For manual extraction with a known passphrase: `steghide extract -sf image.jpg -p 'passphrase'`.

---

## Official References

- [stegseek (GitHub)](https://github.com/RickdeJager/stegseek)
