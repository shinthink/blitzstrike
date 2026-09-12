# hashdeep

- **Category**: Forensics / File Integrity
- **Risk Level**: 🟢 Low

---

## Description

Recursively computes multiple hash digests (MD5, SHA-1, SHA-256, Tiger, Whirlpool) for files and optionally matches them against known hash sets. Supports audit mode to verify file integrity by comparing against a baseline. Part of the md5deep suite. Essential for evidence integrity verification, baseline comparison, and known-file filtering (e.g., NSRL hash sets to exclude known OS files from analysis).

## Installation

```bash
sudo apt install hashdeep
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-c <algs>` | Compute hashes only; defaults are MD5 and SHA-256 (md5,sha1,sha256,tiger,whirlpool) |
| `-r` | Recursive mode; all subdirectories are traversed |
| `-k <file>` | Add a file of known hashes |
| `-a` | Audit mode; validate files against known hashes (requires `-k`) |
| `-x` | Negative matching mode; report files NOT in the known set (requires `-k`) |
| `-l` | Print relative paths for filenames |
| `-b` | Print only bare name of files; all path information omitted |
| `-e` | Compute estimated time remaining for each file |
| `-j <n>` | Use n threads (default: 4) |
| `-m` | Matching mode; report files that match the known set (requires `-k`) |
| `-M` | Like -m but also display hashes of matching files |
| `-X` | Like -x but also display hashes of non-matching files |
| `-p <size>` | Piecewise mode; files are broken into blocks for hashing |
| `-d` | Output in DFXML (Digital Forensics XML) format |
| `-s` | Silent mode; suppress all error messages |
| `-o <type>` | Only process certain types of files (f=files, d=dirs, e=errors) |

## Common Commands

```bash
# Compute SHA-256 hashes for all files recursively
hashdeep -c sha256 -r /mnt/evidence/

# Compute multiple hashes simultaneously (MD5 + SHA-256)
hashdeep -c md5,sha256 -r /mnt/evidence/

# Create a baseline hash set for integrity monitoring
hashdeep -c sha256 -r /mnt/evidence/ > baseline.txt

# Audit mode: verify files against a baseline (report matches)
hashdeep -c sha256 -r -a -k baseline.txt /mnt/evidence/

# Negative match: find new or changed files not in the baseline
hashdeep -c sha256 -r -x -k baseline.txt /mnt/evidence/

# Use relative paths for portable baselines
hashdeep -c sha256 -r -l /mnt/evidence/ > baseline_relative.txt

# Multi-threaded hashing for large evidence sets
hashdeep -c sha256 -r -j 4 -e /mnt/evidence/

# Filter against NSRL hash set (exclude known OS files)
hashdeep -c md5,sha256 -r -x -k nsrl_hashes.txt /mnt/evidence/

# Hash only files, suppress directory entries and errors
hashdeep -c sha256 -r -o f /mnt/evidence/

# Bare filenames for cleaner output
hashdeep -c sha256 -r -b /mnt/evidence/
```

## Notes & Tips

1. Use `-a` (audit/positive match) to verify that files remain unchanged from a baseline; use `-x` (negative match) to identify files that are new or have been modified.
2. Always create baselines with the same algorithm set (`-c`) that will be used for later auditing -- algorithm mismatch causes audit failures.
3. Use `-l` (relative paths) when creating portable baselines that may be verified on different mount points.
4. NSRL (National Software Reference Library) hash sets can be loaded with `-k` to filter out known OS and application files, reducing analysis scope to unknown/suspicious files.
5. Multi-thread with `-j` on large evidence volumes -- hashing is I/O-bound, so gains depend on storage speed.
6. hashdeep output is compatible with other md5deep suite tools (`md5deep`, `sha256deep`) for cross-verification.
7. For chain-of-custody documentation, save baseline files alongside evidence and record the hashdeep command used.

---

## Official References

- [hashdeep GitHub](https://github.com/jessek/hashdeep)
- [Kali hashdeep](https://www.kali.org/tools/hashdeep/)
