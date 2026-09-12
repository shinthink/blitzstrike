# YARA

- **Category**: Forensics / Malware Analysis
- **Risk Level**: 🟢 Low

---

## Description

YARA is a pattern matching tool for malware researchers. It identifies and classifies malware samples by matching binary patterns, strings, and conditions defined in YARA rules. Rules can match hex sequences, text strings, regular expressions, and complex boolean conditions. Widely used in incident response, threat hunting, and forensic triage.

## Installation

```bash
sudo apt install yara
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-r` | Recursively scan directories |
| `-s` | Print matching strings |
| `-n` | Print only not satisfied rules (negate) |
| `-c` | Print only number of matches |
| `-t <tag>` | Only run rules tagged with specified tag |
| `-i <identifier>` | Print only rules named IDENTIFIER |
| `-p <threads>` | Number of threads |
| `-w` | Disable warnings |
| `-m` | Print metadata |
| `-e` | Print namespace |
| `-d <var>=<value>` | Define external variable |
| `-x <module>=<file>` | Pass file's content as extra data to module |
| `-C` | Load pre-compiled rules |
| `-f`, `--fast-scan` | Fast matching mode (skip non-matching files quickly) |

## Common Commands

### Scenario 1: Scan files with rules

```bash
# Scan a file with a single rule file
yara rules.yar suspicious_file.exe

# Scan with multiple rule files
yara rule1.yar rule2.yar target_directory/

# Recursive directory scan
yara -r rules.yar /tmp/malware_samples/
```

### Scenario 2: Show matching details

```bash
# Print matching strings with offsets
yara -s rules.yar sample.bin

# Print metadata from matching rules
yara -m rules.yar sample.bin

# Count matches only
yara -c rules.yar sample.bin
```

### Scenario 3: Write custom rules

```bash
# Create a simple YARA rule
cat > /tmp/detect_webshell.yar << 'RULE'
rule PHP_Webshell {
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "high"
    strings:
        $s1 = "eval(base64_decode" ascii
        $s2 = "system($_" ascii
        $s3 = "passthru(" ascii
        $s4 = "shell_exec(" ascii
    condition:
        any of them
}
RULE

# Scan web root with custom rule
yara -r /tmp/detect_webshell.yar /var/www/
```

### Scenario 4: Threat hunting with community rules

```bash
# Download YARA rules from Awesome YARA or YARA-Rules project
git clone https://github.com/Yara-Rules/rules.git /opt/yara-rules

# Scan disk image mount point with community rules
yara -r /opt/yara-rules/malware/*.yar /mnt/evidence/

# Filter by tag
yara -r -t ransomware /opt/yara-rules/malware/*.yar /mnt/evidence/
```

### Scenario 5: Use compiled rules for performance

```bash
# Compile rules for faster repeated use (done by yarac)
yarac rules_dir/*.yar /tmp/compiled_rules

# Scan with compiled rules
yara -C /tmp/compiled_rules /tmp/samples/
```

## Notes & Tips

1. YARA rules are the industry standard for malware identification and are supported by most SIEM and EDR platforms
2. Use `-p` to parallelize scanning across CPU cores for large evidence sets
3. Community rule sets (YARA-Rules, Florian Roth's signature-base) provide thousands of pre-built detections
4. Combine with `find` for targeted scanning: `find /mnt -name '*.exe' -exec yara rules.yar {} \;`
5. YARA modules (PE, ELF, math, hash) enable advanced conditions like import table matching and entropy checks

---

## Official References

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA (GitHub)](https://github.com/VirusTotal/yara)
- [yara — Kali Tools](https://www.kali.org/tools/yara/)
