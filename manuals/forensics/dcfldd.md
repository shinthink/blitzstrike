# dcfldd

- **Category**: Forensics / Disk Imaging
- **Risk Level**: 🟡 Medium

---

## Description

Enhanced version of GNU `dd` with forensic features developed by the U.S. Department of Defense Computer Forensics Laboratory (DCFL). Adds on-the-fly hashing (MD5, SHA-1, SHA-256, SHA-384, SHA-512), split output files, progress reporting, verification mode, hash logging, and pattern wiping. Designed for forensic disk imaging where integrity verification and audit trails are critical.

## Installation

```bash
sudo apt install dcfldd
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `if=FILE` | Input file or device |
| `of=FILE` | Output file or device |
| `bs=BYTES` | Block size for read/write (default 32768) |
| `hash=ALGORITHM` | Hash algorithm: md5, sha1, sha256, sha384, sha512 |
| `hashlog=FILE` | Log hash output to file |
| `hashwindow=BYTES` | Hash every N bytes (piecewise hashing) |
| `hashconv=before/after` | Hash data before or after conversions |
| `split=BYTES` | Split output into files of N bytes |
| `splitformat=FMT` | Format for split file extensions: `TEXT` (numeric), `MAC`, or `WIN` |
| `errlog=FILE` | Log errors to file |
| `vf=FILE` | Verify output against file |
| `statusinterval=N` | Update the status message every N blocks |
| `textpattern=TEXT` | Fill output with repeating text pattern |
| `pattern=HEX` | Fill output with repeating hex pattern |

## Common Commands

```bash
# Create forensic image with MD5 and SHA-256 hashing
dcfldd if=/dev/sda of=evidence.dd bs=4096 hash=md5,sha256 hashlog=evidence.hash

# Image a disk with progress updates every 1000 blocks
dcfldd if=/dev/sda of=evidence.dd bs=4096 hash=sha256 hashlog=evidence.hash statusinterval=1000

# Split output into 2GB segments with hashing
dcfldd if=/dev/sda of=evidence.dd bs=4096 hash=sha256 hashlog=evidence.hash split=2G splitformat=000

# Piecewise hashing (hash every 1GB chunk)
dcfldd if=/dev/sda of=evidence.dd bs=4096 hash=sha256 hashwindow=1G hashlog=piecewise.hash

dcfldd if=/dev/sda vf=evidence.dd

# Wipe a disk with zero pattern
dcfldd pattern=00 of=/dev/sda bs=4096

# Wipe a disk with text pattern
dcfldd textpattern=WIPED of=/dev/sda bs=4096

# Image to multiple destinations simultaneously
dcfldd if=/dev/sda of=evidence1.dd of=evidence2.dd bs=4096 hash=sha256 hashlog=evidence.hash

# Log errors during imaging
dcfldd if=/dev/sda of=evidence.dd bs=4096 hash=sha256 hashlog=evidence.hash errlog=errors.log
```

## Notes & Tips

1. Always use `hash=` and `hashlog=` when creating forensic images to maintain chain of custody and verify integrity.
2. The `vf=` option compares input to an existing file byte-by-byte -- use it to verify that an image matches the source device.
3. Use `split=` for large drives to create manageable file segments; the `splitformat=` option controls the extension format (`TEXT`, `MAC`, or `WIN`).
4. `hashwindow=` enables piecewise hashing, which allows partial verification if an image segment is corrupted.
5. Unlike standard `dd`, dcfldd shows progress by default. Use `statusinterval=` to adjust the reporting frequency.
6. For write operations (`of=/dev/sdX`, pattern wiping), double-check the target device -- writes are destructive and irreversible.
7. Multiple hash algorithms can be specified simultaneously with comma separation: `hash=md5,sha256`.

---

## Official References

- [Kali dcfldd](https://www.kali.org/tools/dcfldd/)
- [dcfldd (GitHub)](https://github.com/resurrecting-open-source-projects/dcfldd)
