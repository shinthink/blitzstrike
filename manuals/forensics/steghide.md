# Steghide

- **Category**: Forensics / Steganography Analysis
- **Risk Level**: 🟢 Low

---

## Description

A steganography tool that can embed secret data into images (JPEG/BMP/WAV/AU) or extract hidden data from suspicious files. A commonly used tool in CTF and forensics scenarios.

## Installation

```bash
sudo apt install steghide
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `embed` | Embed data in cover file |
| `extract` | Extract hidden data |
| `info <file>` | Display information about a cover/stego file |
| `encinfo` | Display list of supported encryption algorithms |
| `-cf <file>` | Select cover file to embed into |
| `-ef <file>` | Select file to be embedded |
| `-sf <file>` | Stego file (output for embed, input for extract) |
| `-xf <file>` | Output filename for extracted data |
| `-p <passphrase>` | Passphrase for embed/extract |
| `-e <algo>[<mode>]` | Encryption algorithm and/or mode (e.g., `aes256 cbc`, `none`) |
| `-z <level>` | Compression level (1=fastest, 9=best; default: compressed) |
| `-Z` | Do not compress data before embedding |
| `-K` | Do not embed CRC32 checksum |
| `-N` | Do not embed the original filename |
| `-f` | Force overwrite existing files |
| `-q` | Quiet mode (suppress info messages) |
| `-v` | Verbose output |

## Common Commands

```bash
# Embed secret data (-ef = embed file, -cf = cover file)
steghide embed -cf image.jpg -ef secret.txt

# Embed with a password
steghide embed -cf image.jpg -ef secret.txt -p "password"

# Extract data (password required)
steghide extract -sf image.jpg
steghide extract -sf image.jpg -p "password" -xf /tmp/extracted.txt

# View embedded information (without extracting)
steghide info image.jpg

# Brute-force password (with stegcracker or steghide-brute)
# stegcracker: older tool, may not be in current Kali repos
# Alternative: use stegseek (much faster, maintained)
stegseek image.jpg /usr/share/wordlists/rockyou.txt
# Or stegcracker if available:
stegcracker image.jpg /usr/share/wordlists/rockyou.txt
```

## Notes & Tips

1. steghide only supports JPEG, BMP, WAV, and AU formats — for PNG use `zsteg`, for other formats try `stegcracker`.
2. If extraction fails with a passphrase, the data may be embedded without encryption — try `steghide extract -sf image.jpg` with an empty passphrase.
3. Always try an empty passphrase first: `steghide extract -sf image.jpg -p ""` — many CTF challenges use no passphrase.
4. Use `steghide info image.jpg` to check if a file contains embedded data before attempting extraction.
5. For fast passphrase brute-forcing, use `stegseek` (see `stegseek.md`) — it is significantly faster than manual steghide attempts.
6. For comprehensive steganography analysis, also run `strings` (quick plaintext extraction), `binwalk` (detect embedded files), and `zsteg` (PNG/BMP LSB detection) alongside steghide.

---

## Official References

- [Steghide Official Site](http://steghide.sourceforge.net/)
- [Stegseek - Recommended Alternative (GitHub)](https://github.com/RickdeJager/stegseek)
