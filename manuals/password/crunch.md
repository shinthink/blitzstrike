# crunch

- **Category**: Password Attacks / Custom Wordlist Generation
- **Risk Level**: 🟢 Low

---

## Description

Generates custom password wordlists based on specified character sets and length rules. Ideal for scenarios with known password patterns (e.g., "company name + 4 digits", specific format passwords). Can generate extremely large wordlist files — watch out for disk space.

## Installation

```bash
sudo apt install crunch
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `min` | Minimum password length |
| `max` | Maximum password length |
| `charset` | Character set to use |
| `-o FILE` | Output to file |
| `-t PATTERN` | Specify pattern (`@`=lowercase, `,`=uppercase, `%`=digit, `^`=special char) |
| `-d N` | Limit maximum consecutive duplicate characters |
| `-b SIZE` | Split output by file size |
| `-c N` | Split output by line count |
| `-l MASK` | Literal character mask |
| `-p WORDS` | Permutation mode |
| `-q FILE` | Read words and permute |

## Common Commands

```bash
# Generate 6-8 digit numeric wordlist
crunch 6 8 0123456789 -o /tmp/num_dict.txt

# Generate 8-character lowercase letters + digits
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o /tmp/alphanumeric.txt

# Using pattern (@=lowercase, ,=uppercase, %=digit, ^=special char)
crunch 9 9 -t admin@@%% -o /tmp/admin_dict.txt   # admin + 2 lowercase + 2 digits
crunch 11 11 -t Company%%%% -o /tmp/company.txt   # Company + 4 digits
# ⚠️ When using -t, the total length (min=max) must equal the length of the pattern string

# Common password pattern (company name + year)
crunch 14 14 -t TargetCorp%%%% -o /tmp/target.txt

# Generate all 4-digit PINs
crunch 4 4 0123456789 -o /tmp/pins.txt

# Generate with gzip compression to save disk (-z gzip)
crunch 8 8 abc123 -z gzip -o /tmp/small_dict.gz

# Permutation mode (generate all permutations of given word sets)
# Note: -p takes individual strings as arguments separated by spaces
crunch 1 1 -p abc 123    # Generates all permutations of ALL provided words: "abc123" and "123abc"
# Note: min/max values are ignored in -p mode but must still be provided as positional args

# Split large wordlist (100MB per part)
crunch 8 8 abcdefghijklmnopqrstuvwxyz -b 100mb -o START
```

## Notes & Tips

1. Generating a full wordlist can consume terabytes of disk space — use `-t` pattern mode or use `-z gzip` to compress output.
2. Use `-t` pattern mode to specify password format — drastically reduces wordlist size for targeted attacks.
3. Combine with `hashcat -a 0` to crack on-the-fly without saving to disk:
   ```bash
   crunch 8 8 abc123 | hashcat -m 0 hash.txt -a 0
   # Hashcat detects stdin automatically when input is piped; no extra flags needed
   ```
4. Use `-b 100mb -o START` to split large wordlists into manageable chunks for distribution or storage.
5. For known patterns (company name + year, name + birthdate), crunch is more targeted than generic wordlists like rockyou.

---

## Official References

- [crunch Debian man page](https://manpages.debian.org/unstable/crunch/crunch.1.en.html)
