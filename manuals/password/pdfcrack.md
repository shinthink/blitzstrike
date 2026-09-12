# PDFCrack

- **Category**: Password Attacks / File Cracking
- **Risk Level**: 🟢 Low

---

## Description

A command-line tool for recovering passwords from PDF files. Supports cracking both user passwords (required to open the document) and owner passwords (controlling print, copy, and edit permissions). Uses brute-force and wordlist attacks against PDF encryption up to version 1.6, including 40-bit RC4, 128-bit RC4, and 128-bit AES. Useful when password-protected PDFs are discovered during engagements and may contain sensitive information such as credentials, network diagrams, or internal documentation.

## Installation

```bash
sudo apt update
sudo apt install pdfcrack
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-f <file>` | Target PDF file to crack |
| `-w <wordlist>` | Use FILE as source of passwords to try |
| `-c <charset>` | Use the characters in STRING as charset |
| `-n <length>` | Skip trying passwords shorter than this |
| `-m <length>` | Stop when reaching this password length |
| `-o` | Work with the owner password |
| `-u` | Work with the user password (default) |
| `-p <password>` | Give user password to speed up breaking owner password |
| `-s`, `--permutate` | Try permutating the passwords |
| `-l <file>` | Load saved state from file (continue cracking) |
| `-q` | Run quietly |
| `-b` | Perform benchmark and exit |

## Common Commands

```bash
# Wordlist attack on user password
pdfcrack -f protected.pdf -w /usr/share/wordlists/rockyou.txt

# Brute-force with lowercase letters, length 1-6
pdfcrack -f protected.pdf -n 1 -m 6 -c "abcdefghijklmnopqrstuvwxyz"

# Brute-force with digits only, length 4-8
pdfcrack -f protected.pdf -n 4 -m 8 -c "0123456789"

# Crack owner password (permissions password)
pdfcrack -f protected.pdf -o -w /usr/share/wordlists/rockyou.txt

# Brute-force owner password with alphanumeric charset
pdfcrack -f protected.pdf -o -n 1 -m 6 -c "abcdefghijklmnopqrstuvwxyz0123456789"

# Wordlist with permutations (appends numbers, toggles case)
pdfcrack -f protected.pdf -w /usr/share/wordlists/rockyou.txt --permutate

# Batch crack multiple PDFs
for pdf in *.pdf; do
  echo "[*] Cracking: $pdf"
  pdfcrack -f "$pdf" -w /usr/share/wordlists/rockyou.txt
done
```

## Notes & Tips

1. pdfcrack is CPU-only — for GPU-accelerated cracking, extract the hash with `pdf2john` and use `hashcat -m 10400` (PDF 1.1-1.3), `-m 10500` (PDF 1.4-1.6), or `-m 10700` (PDF 1.7 AES-256).
2. Owner passwords are typically weaker than user passwords and only restrict permissions (print, copy, edit) — cracking them does not decrypt the document content.
3. Start with a wordlist attack before brute-force — most real-world PDF passwords are in common wordlists.
4. Supports PDF versions up to 1.6. For PDF 1.7+ (AES-256), use `hashcat` or `john` instead.
5. PIN-style numeric passwords (4-6 digits) are very fast to brute-force with `-c "0123456789"`.

---

## Official References

- [pdfcrack on SourceForge](https://pdfcrack.sourceforge.net/)
- [Kali pdfcrack](https://www.kali.org/tools/pdfcrack/)
