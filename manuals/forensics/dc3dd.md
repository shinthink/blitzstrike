# dc3dd

- **Category**: Forensics / Disk Imaging
- **Risk Level**: 🟢 Low

---

## Description

A patched version of GNU dd designed for forensic disk imaging. Adds capabilities missing from standard dd: on-the-fly hashing (MD5/SHA1/SHA256/SHA512), automatic split output, built-in error recovery, detailed progress reporting, and operation logging. Creates forensically sound images with integrated hash verification — the standard for maintaining chain of custody during evidence collection.

## Installation

```bash
sudo apt install dc3dd
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `if=<source>` | Input: device or file to image |
| `of=<dest>` | Output: image file destination (single file, no hashing) |
| `hof=<file>` | Output file with hash computation enabled (single file, hash-verified) |
| `ofs=<base>` | Split output: base filename pattern for split output set (e.g., `ofs=/mnt/evidence/disk.img` produces `disk.img.000`, `disk.img.001`, …) |
| `hofs=<base>` | Hash-verified split output: like `ofs=` but also hashes each chunk and cross-verifies against input hash |
| `ofsz=<size>` | Maximum size per split file when using `ofs=` or `hofs=` (e.g., `ofsz=4G`) |
| `hash=<alg>` | Hash algorithm: `md5`, `sha1`, `sha256`, `sha512` |
| `hlog=<file>` | Save computed hash values to a log file |
| `bufsz=<size>` | Internal buffer size (must be a multiple of sector size; e.g., `512k` for speed) |
| `cnt=<n>` | Number of blocks to copy |
| `log=<file>` | General operation log |

## Common Commands

```bash
# Image a disk with SHA256 hash verification
dc3dd if=/dev/sdb hof=/mnt/evidence/disk.img hash=sha256 hlog=/mnt/evidence/hash.log bufsz=512k

# Image and split into 4GB hash-verified chunks (useful for FAT32 storage)
dc3dd if=/dev/sdb hofs=/mnt/evidence/disk.img hash=sha256 hlog=/mnt/evidence/hash.log ofsz=4G bufsz=512k

# Compute both MD5 and SHA256 simultaneously
dc3dd if=/dev/sdb hof=/mnt/evidence/disk.img hash=md5 hash=sha256 hlog=/mnt/evidence/hashes.log

# Image to two destinations simultaneously (backup + working copy)
dc3dd if=/dev/sdb of=/mnt/backup/disk.img of=/mnt/working/disk.img hash=sha256

# Forensic wipe of a disk (overwrite with zeros, with verification)
dc3dd if=/dev/zero of=/dev/sdb bufsz=512k hash=sha256
```

## Notes & Tips

1. Always specify `hlog=` to create a chain-of-custody record — the log proves the image is unmodified.
2. Use `bufsz=512k` or larger for significantly faster imaging — the default 512-byte block size is very slow on large drives.
3. `hof=` writes a single hash-verified output file; `hofs=` + `ofsz=` writes hash-verified split chunks. Use `of=` only when hash verification is not needed.
4. For SSDs with wear-leveling, always image at the block device level (`/dev/sdb`) — data exists in areas outside mounted partitions.
5. `dcfldd` is an equivalent alternative — both produce court-admissible forensic images.

---

## Official References

- [dc3dd Debian man page](https://manpages.debian.org/dc3dd/dc3dd.1.en.html)
- [Kali dc3dd](https://www.kali.org/tools/dc3dd/)
