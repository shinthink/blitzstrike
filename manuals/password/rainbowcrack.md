# rainbowcrack

- **Category**: Password Attacks / Rainbow Table Cracking
- **Risk Level**: 🟡 Medium

---

## Description

A hash cracker that uses precomputed rainbow tables to trade disk space for cracking speed. Unlike hashcat (which computes hashes on the fly), rainbowcrack looks up hashes in precomputed tables — cracking can be near-instantaneous once tables exist. Most effective for unsalted hashes (LM, NTLM, MD5 without salt). Includes `rtgen` for generating custom tables and `rtsort` for sorting them before use.

## Installation

```bash
sudo apt install rainbowcrack
```

## Parameter Reference

### rcrack (main cracking tool)

| Parameter | Description |
|-----------|-------------|
| `<path>` | Directory containing rainbow table files (`*.rt` or `*.rtc`); multiple paths are supported |
| `-h <hash>` | Single hash to crack |
| `-l <file>` | File containing hashes to crack (one per line) |
| `-lm <file>` | pwdump file containing LM hashes |
| `-ntlm <file>` | pwdump file containing NTLM hashes |

### rtgen (table generation tool)

| Parameter | Description |
|-----------|-------------|
| `<hash_algorithm>` | Hash type: `lm`, `ntlm`, `md5`, `sha1`, or `sha256` |
| `<charset>` | Character set: `loweralpha`, `mixalpha-numeric`, etc. |
| `<min_len>` | Minimum password length |
| `<max_len>` | Maximum password length |
| `<table_index>` | Table index (use different values to avoid overlap) |
| `<chain_len>` | Chain length (longer = more coverage, larger file) |
| `<chain_num>` | Number of chains |
| `<part_index>` | Table part index |
| `-bench` | Benchmark table generation for the selected algorithm, charset, length range, and table index |

## Common Commands

```bash
# Crack a single NTLM hash using existing tables
rcrack /path/to/ntlm_tables/ -h 32ed87bdb5fdc5e9cba88547376818d4

# Crack multiple hashes from file
rcrack /path/to/ntlm_tables/ -l hashes.txt

# Download pre-generated tables (recommended — generation takes days)
# NTLM/LM tables: https://ophcrack.sourceforge.io/tables.php
# Free tables:    https://www.freerainbowtables.com/

# Generate NTLM rainbow table for lowercase letters, length 1-8
rtgen ntlm loweralpha 1 8 0 3800 33554432 0
rtsort *.rt

# Crack MD5 hash using generated tables
rtgen md5 mixalpha-numeric 1 7 0 3800 33554432 0
rtsort *.rt
rcrack ./ -h 098f6bcd4621d373cade4e832627b4f6
```

## Notes & Tips

1. Download precomputed NTLM tables rather than generating — table generation for useful charset/length combinations takes days.
2. Rainbow tables only work on unsalted hashes — bcrypt, scrypt, and Argon2 hashes cannot be cracked this way.
3. NTLM (Windows) and LM (legacy Windows) are the primary targets — tables for these are widely available for free.
4. For salted hashes or modern algorithms (bcrypt, NetNTLMv2), use hashcat instead.
5. The time/space tradeoff: larger tables = better coverage but more disk space; chain length and table count control this balance.

---

## Official References

- [Kali rainbowcrack](https://www.kali.org/tools/rainbowcrack/)
- [Kali rainbowcrack package tracker](https://pkg.kali.org/pkg/rainbowcrack)
