# foremost

- **Category**: Forensics / File Recovery
- **Risk Level**: 🟢 Low

---

## Description

A file recovery tool based on file header/footer signatures. Recovers deleted files from disk images, memory dumps, or raw data streams. Supports common formats including JPEG, PNG, GIF, BMP, AVI, EXE, ZIP, and PDF. Functionally similar to `scalpel` (an enhanced successor to foremost).

## Installation

```bash
sudo apt install foremost
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-i <file>` | Specify input file (default is stdin) |
| `-o <dir>` | Output directory (default: output) |
| `-t <type>` | Specify file type (e.g., `-t jpeg,pdf`) |
| `-d` | Turn on indirect block detection (for UNIX file-systems) |
| `-a` | Write all headers, perform no error detection (corrupted files) |
| `-w` | Only write the audit file, do not write detected files to disk |
| `-q` | Quick mode; searches performed on 512-byte boundaries |
| `-Q` | Quiet mode; suppress output messages |
| `-v` | Verbose mode |
| `-T` | Use timestamp as output directory name |
| `-c <file>` | Set configuration file to use (defaults to foremost.conf) |

## Common Commands

```bash
# Recover all supported file types
foremost -i disk.img -o /tmp/recovered/

# Recover images only (faster)
foremost -t jpg,png,gif -i disk.img -o /tmp/recovered/

# Recover documents only
# Note: foremost 'doc' recovers OLE2-format .doc files; 'zip' recovers OOXML .docx/.xlsx/.pptx (ZIP-based)
foremost -t pdf,doc,zip -i disk.img -o /tmp/recovered/

# Verbose mode (show file offsets as found)
foremost -v -i disk.img -o /tmp/recovered/

# Recover files from a memory dump
foremost -i memory.dmp -o /tmp/mem_recovered/ -t jpg,png,zip

# View recovery summary
cat /tmp/recovered/audit.txt
```

## Notes & Tips

1. foremost is non-destructive — it reads the input file but never modifies it; safe to run against original evidence images.
2. Recovered files are sorted into subdirectories by type (e.g., `jpg/`, `pdf/`, `zip/`) and numbered sequentially.
3. The `audit.txt` file in the output directory lists all recovered files with their offsets — review it first to understand what was found.
4. Use `-t zip` to recover ZIP files, which also captures DOCX, XLSX, PPTX (all ZIP-based formats) from disk images.
5. When foremost misses files, try `scalpel` (more configurable) or `photorec` (broader format support with a text UI).

---

## Official References

- [Foremost (SourceForge)](http://foremost.sourceforge.net/)
- [Kali foremost](https://www.kali.org/tools/foremost/)
