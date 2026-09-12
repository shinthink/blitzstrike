# hashcat

- **Category**: Password Attacks / Offline Hash Cracking
- **Risk Level**: 🟢 Low

---

## Description

The world's fastest GPU-accelerated hash cracking tool. Supports 450+ hash types with dictionary attacks, rule-based attacks, mask attacks (brute-force), and hybrid attacks. Requires a GPU for best performance; can also run on CPU but much slower.

## Installation

```bash
sudo apt install hashcat
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-I` | Show system/environment/backend API info |
| `-m N` | Hash-type (see type table below, otherwise autodetect) |
| `-a N` | Attack-mode (see references below) |
| `-o FILE` | Define outfile for recovered hash |
| `--show` | Compare hashlist with potfile; show cracked hashes |
| `--left` | Show uncracked hashes |
| `-r FILE` | Rules file (multiple rules applied to each word from wordlists) |
| `--force` | Ignore warnings |
| `-w N` | Enable a specific workload profile (see pool below) |
| `--status` | Enable automatic update of the status screen |
| `--increment` | Mask increment mode |
| `--increment-min N` | Start mask incrementing at N |
| `--increment-max N` | Stop mask incrementing at N |

### Common Hash Types (-m parameter)

| Value | Type | Typical Scenario |
|-------|------|-----------------|
| 0 | MD5 | General |
| 100 | SHA1 | General |
| 1400 | SHA2-256 | General |
| 1000 | NTLM | Windows password hash |
| 3000 | LM | Legacy Windows |
| 5600 | NetNTLMv2 | Responder capture |
| 5500 | NetNTLMv1 | Legacy Windows |
| 13100 | Kerberos TGS | Kerberoasting |
| 18200 | Kerberos AS-REP | AS-REP Roasting |
| 3200 | bcrypt | Linux/Web passwords |
| 1800 | sha512crypt | Linux shadow |
| 500 | md5crypt | Linux shadow (old) |
| 400 | phpass | WordPress/Joomla/phpBB3 (MD5) |
| 1600 | Apache MD5 | Apache .htpasswd (apr1) |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | WPA/WPA2 wireless cracking |
| 8900 | scrypt | Cryptocurrency wallets / web apps |
| 34000 | Argon2 | Modern password storage (hashcat 6.2.6+) |

## Common Commands

```bash
# Decompress wordlist if needed (modern Kali 2023+ ships rockyou.txt pre-extracted)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz  # Only if .gz exists and .txt is missing

# Dictionary attack (most common)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt   # NTLM
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt   # NetNTLMv2
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt      # MD5

# Rule-based attack (variant generation, much more effective than plain dictionary)
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
# Note: Multiple -r flags can be chained (rules are applied left-to-right):
# hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rule1.rule -r rule2.rule

# Mask attack (brute-force specific format)
# Character sets: ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all
hashcat -m 0 -a 3 hashes.txt ?u?l?l?l?d?d?d?d   # 1 uppercase + 3 lowercase + 4 digits
hashcat -m 0 -a 3 hashes.txt ?d?d?d?d?d?d        # 6-digit number
hashcat -m 0 -a 3 hashes.txt Password?d?d?d?d    # Password + 4 digits

# Incremental length mask
hashcat -m 0 -a 3 hashes.txt --increment --increment-min 6 --increment-max 8 ?l?l?l?l?l?l?l?l

# Crack Kerberoasting hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack AS-REP Roasting hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack WPA/WPA2 handshakes (PMKID+EAPOL)
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt

# Show already-cracked results
hashcat -m 1000 hashes.txt --show

# CPU mode (when no GPU available)
# --force is required when running without a GPU; suppresses the "No devices found" error
hashcat -m 0 hashes.txt wordlist.txt --force

# High-performance mode
hashcat -m 0 -a 0 hashes.txt wordlist.txt -w 3
```

### Common Rule Files

```bash
ls /usr/share/hashcat/rules/
# best64.rule        - 64 best rules, fast and practical
# rockyou-30000.rule - 30000 rules, broader coverage
# dive.rule          - Deep rules (slow but wide coverage)
# d3ad0ne.rule       - Classic rule set
```

## Notes & Tips

1. Always use `--force` when running on CPU (no GPU) — without it hashcat exits with "No devices found".
2. Save cracked results with `-o cracked.txt` and review them later with `hashcat --show`.
3. Rule-based attacks (`-a 0 -r best64.rule`) are far more effective than plain dictionary attacks — always add a rule file.
4. GPU driver issues are the most common cause of failures — ensure your GPU drivers are installed and up to date.
5. Use `-w 3` (high workload) for maximum speed when the machine is dedicated to cracking; use `-w 1` to keep the system usable.

---

## Official References

- [Hashcat Wiki](https://hashcat.net/wiki/)
- [Hashcat (GitHub)](https://github.com/hashcat/hashcat)
- [Hashcat Official Site](https://hashcat.net/hashcat/)
