# ssdeep

- **Category**: Forensics / Fuzzy Hashing
- **Risk Level**: 🟢 Low

---

## Description

Computes and compares context-triggered piecewise hashing (CTPH / fuzzy hashes). Unlike cryptographic hashes (MD5, SHA), fuzzy hashes detect similarity between files even when partially modified. Based on the spamsum algorithm. Essential for malware analysis (identifying variants from a known sample), forensic triage (finding similar documents across seized media), and deduplication of large evidence sets.

## Installation

```bash
sudo apt install ssdeep
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-b` | Uses only the bare name of files; all path information omitted |
| `-l` | Use relative paths for filenames |
| `-r` | Recursive mode |
| `-s` | Silent mode; all errors are suppressed |
| `-m <file>` | Match input files against known hashes in file |
| `-k <file>` | Match signatures in files against signatures in file |
| `-p` | Pretty matching mode; similar to -d but includes all matches |
| `-g` | Cluster matches together |
| `-d` | Directory mode; compare all files in a directory |
| `-x` | Compare files as signature files |
| `-a` | Display all matches regardless of score |
| `-t <n>` | Only display matches above the given threshold |
| `-c` | Output in CSV format |
| `-v` | Verbose mode; display filename as it is being processed |

## Common Commands

```bash
# Compute fuzzy hash for a single file
ssdeep malware_sample.exe

# Compute fuzzy hashes for all files in a directory recursively
ssdeep -r /mnt/evidence/

# Save hashes to a baseline file
ssdeep -r /mnt/evidence/ > known_hashes.txt

# Match files against known hash set
ssdeep -m known_hashes.txt suspect_file.bin

# Recursively match a directory against known hashes
ssdeep -r -m known_hashes.txt /mnt/suspect_drive/

# Compare all input files against each other (find similar pairs)
ssdeep -d -r /mnt/evidence/samples/

# Compare with a minimum similarity threshold of 50%
ssdeep -d -t 50 -r /mnt/evidence/samples/

# Output in CSV format for scripted processing
ssdeep -c -r /mnt/evidence/ > hashes.csv

# Bare filenames (no path) for cleaner output
ssdeep -b -r /mnt/evidence/

# Match files from a list on stdin
find /mnt/evidence -name "*.doc" | ssdeep -l -m known_hashes.txt
```

## Notes & Tips

1. Fuzzy hashing detects similarity, not identity -- a high match score (e.g., 90+) indicates near-identical content, but even low scores (e.g., 30) can reveal meaningful relationships between files.
2. Use `-d` to find similar files within a dataset (e.g., malware variant clustering); use `-m` to match unknown files against a known hash database.
3. The `-t` threshold flag filters noise -- start with a threshold of 50 and lower it if important matches are missed.
4. Combine with YARA rules for layered malware detection: ssdeep identifies variants by similarity, YARA matches by pattern.
5. Fuzzy hashes are order-dependent -- the same bytes in a different order produce different hashes. This is by design for detecting content modifications.
6. For large-scale forensic triage, pipe output through standard tools or use CSV mode (`-c`) for database ingestion.
7. ssdeep hashes are not suitable for integrity verification -- use cryptographic hashes (SHA-256) for chain-of-custody purposes.

---

## Official References

- [ssdeep Official Site](https://ssdeep-project.github.io/ssdeep/)
- [Kali ssdeep](https://www.kali.org/tools/ssdeep/)
