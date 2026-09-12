# hashID

- **Category**: Password Attacks / Hash Identification
- **Risk Level**: 🟢 Low

---

## Description

Identifies the type of a hash string by analyzing its format, length, and character set. Supports 220+ hash types and provides the corresponding hashcat mode number and john format string. An essential first step before running hashcat or john — using the wrong algorithm wastes cracking time and produces no results.

## Installation

```bash
sudo apt install hashid
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<hash>` | Single hash string to identify |
| `-m` | Show hashcat mode numbers |
| `-j` | Show john format strings |
| `-e` | Extended mode (show all possible matches, not just most likely) |
| `-o <file>` | Save output to file |

## Common Commands

```bash
# Identify a single hash
hashid '5f4dcc3b5aa765d61d8327deb882cf99'

# Show with hashcat mode numbers
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'

# Show with john format strings
hashid -j '$6$rounds=5000$salt$hash...'

# Read multiple hashes from a file
hashid -m -j hashes.txt

# Extended mode (show all possible types)
hashid -e '098f6bcd4621d373cade4e832627b4f6'

# Typical workflow: identify → crack
hashid -m 5f4dcc3b5aa765d61d8327deb882cf99
# Output: MD5 [Hashcat Mode: 0]
hashcat -m 0 5f4dcc3b5aa765d61d8327deb882cf99 /usr/share/wordlists/rockyou.txt
```

## Notes & Tips

1. hashid narrows down possibilities but cannot guarantee the exact type — test the most likely candidates first.
2. Common hash types to recognize by sight: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex), bcrypt (`$2y$` prefix), NTLM (32 hex but different context), NetNTLMv2 (contains `:::`)
3. If hashid shows multiple possibilities, start with the simplest algorithm — MD5 cracks fastest, then SHA1, then SHA256.
4. For NTLM hashes from Windows (format: `User:RID:LM:NTLM:::`), use hashcat mode 1000 targeting the NTLM portion.
5. Alternative tools: `hash-identifier` (pre-installed on Kali) and `name-that-hash` (more modern, better accuracy for ambiguous hashes).

---

## Official References

- [hashid (GitHub)](https://github.com/psypanda/hashID)
- [Kali hashid](https://www.kali.org/tools/hashid/)
