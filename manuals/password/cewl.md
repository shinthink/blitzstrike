# CeWL

- **Category**: Password Attacks / Custom Wordlist Generation
- **Risk Level**: 🟢 Low

---

## Description

A web content crawling wordlist generation tool that scrapes text from a target website to generate a customized password wordlist. Because people tend to use work-related words as passwords, vocabulary from the target's own website is often more targeted than generic wordlists.

## Installation

```bash
sudo apt install cewl
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d N` | Crawl depth (default 2) |
| `-m N` | Minimum word length (default 3) |
| `-x N` | Maximum word length (default unset) |
| `-w FILE` | Write the output to the file |
| `-a` / `--meta` | Include meta data |
| `--email` | Include email addresses |
| `--lowercase` | Lowercase all parsed words |
| `--with-numbers` | Accept words with numbers as well as just letters |
| `--auth_type` | Authentication type (digest or basic) |
| `--auth_user` | Authentication username |
| `--auth_pass` | Authentication password |

## Common Commands

```bash
# Basic crawl, minimum 6-character words
cewl http://target.com -m 6 -w /tmp/target_wordlist.txt

# Crawl depth 3, extract emails
cewl http://target.com -d 3 -m 5 --email -w /tmp/wordlist.txt

# Crawl HTTPS
cewl https://target.com -m 6 -w /tmp/wordlist.txt

# Add numeric variants (combine with john rules)
cewl http://target.com -m 6 -w /tmp/base.txt
john --wordlist=/tmp/base.txt --rules --stdout > /tmp/expanded.txt
# Or use hashcat rules to expand:
hashcat --stdout /tmp/base.txt -r /usr/share/hashcat/rules/best64.rule > /tmp/expanded.txt

# Crawl pages requiring authentication
cewl http://target.com --auth_user admin --auth_pass password -m 6 -w /tmp/wordlist.txt
```

## Notes & Tips

1. Run cewl with `-d 3` (depth 3) to collect from more pages — greater depth yields more words.
2. Combine cewl output with existing wordlists using `cat`: `cat cewl_output.txt rockyou.txt | sort -u > combined.txt`.
3. Use `-m 6` to filter out very short words that rarely appear as passwords.
4. The `--email` flag collects email addresses in addition to words — useful for username discovery.
5. After generating a custom wordlist, use hashcat rule-based mutation (`-r rules/best64.rule`) to expand it further.

---

## Official References

- [CeWL (GitHub)](https://github.com/digininja/CeWL)
