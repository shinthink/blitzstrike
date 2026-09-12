# Name-That-Hash

- **Category**: Password Attacks / Hash Identification
- **Risk Level**: 🟢 Low

---

## Description

Modern hash type identifier and successor to `hashid`. Identifies hash types from raw hash strings and provides corresponding hashcat mode numbers and john format names. Offers more accurate identification than `hashid` with better output formatting, confidence ranking, and support for newer hash types. Designed for both interactive use and scripting pipelines.

## Installation

```bash
sudo apt install name-that-hash
# Or install via pip
pip3 install name-that-hash
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-t <hash>` | Identify a single hash string |
| `-f <file>` | Identify hashes from a file (one per line) |
| `-g` | Greppable output (JSON format) |
| `-b64` | Decode hashes in Base64 before identification |
| `-e`, `--extreme` | Search for hashes within a string |
| `-a` | Accessible output mode (no ASCII art) |
| `-v` | Verbose/debugging logs (-vvv for maximum) |
| `--no-banner` | Suppress the banner |
| `--no-john` | Hide John The Ripper format suggestions |
| `--no-hashcat` | Hide Hashcat mode suggestions |

## Common Commands

```bash
# Identify a single hash
nth -t '5f4dcc3b5aa765d61d8327deb882cf99'

# Identify a hash with accessible output
nth -t '5f4dcc3b5aa765d61d8327deb882cf99' -a

# Batch identify hashes from a file
nth -f hashes.txt

# Greppable output for scripting
nth -t '5f4dcc3b5aa765d61d8327deb882cf99' -g

# Pipe from other tools (e.g., extract and identify)
cat /etc/shadow | awk -F: '{print $2}' | nth -f -

# Identify without banner (clean output)
nth -t '5f4dcc3b5aa765d61d8327deb882cf99' --no-banner

# Show only hashcat modes (hide john formats)
nth -t '5f4dcc3b5aa765d61d8327deb882cf99' --no-john

# Typical workflow: identify hash then crack
nth -t '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
# Output: bcrypt [Hashcat Mode: 3200] [John Format: bcrypt]
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

### Common Hash Signatures

| Pattern | Likely Type | hashcat Mode |
|---------|-------------|--------------|
| 32 hex chars | MD5 | 0 |
| 40 hex chars | SHA-1 | 100 |
| 64 hex chars | SHA-256 | 1400 |
| `$2y$` or `$2a$` prefix | bcrypt | 3200 |
| `$6$` prefix | sha512crypt | 1800 |
| `$1$` prefix | md5crypt | 500 |

## Notes & Tips

1. Use `nth` (the CLI alias) instead of typing `name-that-hash` — it is the standard invocation.
2. `name-that-hash` ranks results by confidence, with the most probable hash type listed first — start cracking with the top result.
3. For ambiguous hashes (e.g., 32-character hex could be MD5, NTLM, or MD4), test the most common algorithm first: MD5 (hashcat mode 0) is far more prevalent than NTLM (mode 1000) in web applications.
4. Greppable output (`-g`) integrates well with automation scripts that need to parse hash types programmatically.
5. Compared to `hashid`: name-that-hash has better accuracy for modern hash types, provides confidence rankings, and displays both hashcat and john references by default.
6. When dealing with hashes extracted from databases, the application framework often determines the hash type — identify the framework (WordPress, Django, etc.) to narrow possibilities.

---

## Official References

- [Name-That-Hash (GitHub)](https://github.com/bee-san/Name-That-Hash)
- [Kali name-that-hash](https://www.kali.org/tools/name-that-hash/)
