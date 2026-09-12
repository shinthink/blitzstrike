# Radare2

- **Category**: Reverse Engineering / Binary Analysis
- **Risk Level**: 🟡 Medium

---

## Description

Binary analysis framework. In this skill, use radare2 only in non-interactive one-shot mode for targeted questions such as function discovery, imports, strings, and selected disassembly snippets.

## Installation

```bash
apt-get update && apt-get install -y radare2
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-q` | Quiet mode |
| `-c <cmd>` | Execute radare command and exit |
| `aaa` | Analyze all |
| `afl` | List functions |
| `izz` | List strings |
| `ii` | List imports |
| `pdf @ <func>` | Print disassembly for function |
| `-A` | Run 'aaa' command to analyze all referenced code on load |

## Common Commands

```bash
# List functions without opening interactive shell
r2 -q -c "aaa; afl" /usr/bin/target

# List imports and strings
r2 -q -c "aaa; ii; izz" /usr/bin/target

# Disassemble main only
r2 -q -c "aaa; pdf @ main" /usr/bin/target
```

## Notes & Tips

1. Do not use long interactive `r2` sessions for agent workflows.
2. Use `rabin2` first for fast metadata; use `radare2` only when targeted disassembly is needed.
3. Treat results as analysis leads and confirm exploitability with runtime or configuration evidence.

---

## Official References

- [radare2 Book](https://book.rada.re/)
- [radare2 GitHub](https://github.com/radareorg/radare2)

