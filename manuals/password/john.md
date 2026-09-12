# John the Ripper

- **Category**: Password Attacks / Offline Hash Cracking
- **Risk Level**: 🟢 Low

---

## Description

John the Ripper is a classic hash cracking tool, excellent at handling Linux shadow files and various encrypted files (ZIP/PDF/RAR/SSH Key, etc.). Features a built-in rule engine that can intelligently generate password variants. Runs on CPU; complements GPU-accelerated hashcat.

## Installation

```bash
sudo apt install john
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `--wordlist=FILE` | Wordlist mode, read words from FILE or stdin |
| `--format=TYPE` | Force hash of type NAME |
| `--rules` | Enable word mangling rules |
| `--rules=RULE` | Enable word mangling rules for specified section |
| `--show` | Show cracked passwords |
| `--list=formats` | List capabilities (see --list=help for options) |
| `--incremental` | Incremental mode (using section MODE) |
| `--mask=MASK` | Mask mode |
| `--restore` | Restore an interrupted session (called NAME) |
| `--session=NAME` | Give a new session the NAME |
| `--pot=FILE` | Pot file to use |

## Common Commands

```bash
# Crack Linux shadow file
john /etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow

# Combine passwd + shadow (improves success rate)
unshadow /etc/passwd /etc/shadow > /tmp/combined.txt
john /tmp/combined.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show already-cracked passwords
john --show /tmp/combined.txt

# Specify hash format
john --format=NT hash.txt                    # NTLM (Windows)
john --format=md5crypt hash.txt              # Linux MD5 crypt
john --format=bcrypt hash.txt               # bcrypt
john --format=Raw-SHA256 hash.txt           # SHA-256 (raw, not salted)
john --format=netntlmv2 hash.txt            # NetNTLMv2 (Responder capture)
# Tip: If john auto-detects the wrong format, always specify --format explicitly

# View supported formats
john --list=formats | grep -i ntlm

# Rule-based attack (generates password variants)
john --wordlist=wordlist.txt --rules hash.txt
john --wordlist=wordlist.txt --rules=Extra hash.txt

# Crack various file passwords (extract hash first)
# Note: On Kali these tools are part of john-the-ripper extra packages
zip2john encrypted.zip > zip_hash.txt && john zip_hash.txt
pdf2john.pl encrypted.pdf > pdf_hash.txt && john pdf_hash.txt
# rar2john for RAR files (may need rar2john from john-extra)
rar2john encrypted.rar > rar_hash.txt && john rar_hash.txt
# ssh2john for SSH private keys (passphrase-protected)
ssh2john id_rsa > ssh_hash.txt && john ssh_hash.txt --wordlist=wordlist.txt

# Brute-force mode
john --incremental hash.txt

# Resume interrupted session
john --restore=session_name
```

## Notes & Tips

1. Always identify the hash type first with `hashid` or `john --list=formats | grep -i <type>` before cracking.
2. John's incremental mode (`--incremental`) tries all character combinations — use it as a last resort as it is very slow.
3. For GPU-accelerated cracking of common hash types, use hashcat instead — John is CPU-based and complements hashcat for specialized formats.
4. The `--rules` flag applies rule-based mutations (capitalization, leetspeak, etc.) that significantly expand a wordlist.
5. `john --show <hashfile>` displays already-cracked hashes from John's pot file — run this if you interrupt a session.

---

## Official References

- [John the Ripper (GitHub)](https://github.com/openwall/john)
- [John the Ripper Official Site](https://www.openwall.com/john/)
