# bulk_extractor

- **Category**: Forensics / Artifact Extraction
- **Risk Level**: 🟢 Low

---

## Description

A high-speed forensic scanner that processes disk images, files, or directories without mounting them and extracts structured artifacts: email addresses, credit card numbers, URLs, phone numbers, MAC addresses, domain names, GPS coordinates, and more. Does not interpret the file system — scans raw bytes, making it effective even on corrupted or fragmented storage. Outputs results to text files organized by artifact type.

## Installation

```bash
sudo apt install bulk-extractor
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<input>` | Input: disk image file, directory, or raw device |
| `-o <dir>` | Output directory (required) |
| `-E <scanner>` | Disable all scanners except the one specified (equivalent to `-x all -e <scanner>`) |
| `-x <scanner>` | Disable a scanner (can be repeated) |
| `-e <scanner>` | Enable a scanner (can be repeated) |
| `-S <name=value>` | Set a scanner option as a name=value pair (can be repeated) |
| `-f <regex>` | Search for a pattern (the `find` scanner; can be repeated) |
| `-F <file>` | Read search patterns from a file (can be repeated) |
| `-Y <start>[-end]` | Specify start (and optional end) byte offset of the area on disk to scan |
| `-r <file>` | File to read the alert ("red") list from |
| `-w <file>` | File to read the stop ("white") list from |
| `-s <frac>[:passes]` | Random sampling — only scan a fraction of the input |
| `-M <n>` | Max recursion depth (default: 12) |
| `-j <n>` | Number of threads (default: 4) |
| `-q` | No status or performance output |
| `-G <n>` | Page size in bytes (default: 16777216) |
| `-R` | Treat image file as a directory to recursively explore |
| `-Z` | Wipe (recursively) the output directory before starting |

### Scanners and Output Features

The scanner name you pass to `-e`/`-x` is **not** always the same as the output filename it produces. Use the exact scanner names from `bulk_extractor -h` ("These scanners enabled/disabled").

Real scanners enabled by default include: `accts`, `aes`, `base64`, `elf`, `email`, `evtx`, `exif`, `facebook`, `find`, `gps`, `gzip`, `httplogs`, `json`, `kml_carved`, `msxml`, `net`, `ntfsindx`, `ntfslogfile`, `ntfsmft`, `ntfsusn`, `pdf`, `rar`, `sqlite`, `utmp`, `vcard_carved`, `windirs`, `winlnk`, `winpe`, `winprefetch`, `zip`.

Scanners disabled by default (enable with `-e`): `base16`, `hiberfile`, `outlook`, `wordlist`, `xor`.

Watch out for output features that are **not** scanner names — passing them to `-e`/`-x` will error:

| Output file | Produced by scanner |
|-------------|---------------------|
| `url.txt`, `domain.txt` | `email` |
| `telephone.txt`, `ccn.txt` (credit cards) | `accts` |
| `gps.txt` | `gps` |

So to limit a run to emails/URLs/domains, enable the `email` scanner (not `url`/`domain`); for phone numbers and credit cards, enable `accts` (not `telephone`/`credit_card`).

## Common Commands

```bash
# Extract all artifacts from a disk image
bulk_extractor -o ./output disk_image.dd

# Process a directory of files
bulk_extractor -o ./output -R /mnt/evidence/

# Only extract email addresses, URLs and domains (all from the email scanner)
bulk_extractor -o ./output -x all -e email disk_image.dd

# Only extract phone numbers and credit card numbers (from the accts scanner)
bulk_extractor -o ./output -x all -e accts disk_image.dd

# Search for a custom pattern (the find scanner)
bulk_extractor -o ./output -f 'password\s*=' disk_image.dd

# Wipe the output dir first, then scan only a byte range of the disk
bulk_extractor -o ./output -Z -Y 0-1073741824 disk_image.dd

# Multi-threaded processing (faster on large images)
bulk_extractor -o ./output -j 8 disk_image.dd

# View extracted emails
cat ./output/email.txt

# View extracted URLs
cat ./output/url.txt

# View extracted credit card numbers
cat ./output/ccn.txt
```

## Notes & Tips

1. bulk_extractor is non-destructive and does not modify the source — safe to run directly against original evidence.
2. Output files are plain text with one artifact per line — easy to grep, sort, and deduplicate.
3. The `email.txt` and `url.txt` outputs frequently reveal credentials, internal systems, and attacker infrastructure in forensic investigations.
4. No file system mounting needed — works on corrupted images, encrypted volumes, and raw partitions where autopsy fails.
5. Use `bulk_extractor -e zip` to extract and examine compressed archives embedded in the disk image.

---

## Official References

- [bulk-extractor (GitHub)](https://github.com/simsong/bulk_extractor)
- [Kali bulk-extractor](https://www.kali.org/tools/bulk-extractor/)
