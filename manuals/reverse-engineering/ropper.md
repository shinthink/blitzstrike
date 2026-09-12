# Ropper

- **Category**: Reverse Engineering / Exploit Development
- **Risk Level**: 🟡 Medium

---

## Description

ropper searches for ROP (Return-Oriented Programming), JOP (Jump-Oriented Programming), and SYS (syscall) gadgets in binary files. It supports ELF, PE, Mach-O, and raw binary formats across multiple architectures including x86, x86_64, ARM, MIPS, and PowerPC. ropper can generate ROP chains automatically for common operations such as execve, mprotect, and virtualprotect. Essential for exploit development when bypassing DEP/NX memory protections.

## Installation

```bash
sudo apt install ropper
```

Alternative:

```bash
pip3 install ropper
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-f, --file <file>` | The file to load |
| `--search <pattern>` | Search for gadgets |
| `--type <type>` | Gadget type: `rop`, `jop`, `sys`, or `all` |
| `--arch <arch>` | The architecture of the loaded file |
| `--inst-count <n>` | Specifies the max count of instructions in a gadget (default: 6) |
| `--chain <generator>` | Generate a ROP chain (e.g., `execve`, `mprotect address=0x... size=0x...`, `virtualprotect address=0x...`) |
| `--nocolor` | Disable colored output |
| `-I <imagebase>` | Use this imagebase for gadgets |
| `--all` | Does not remove duplicate gadgets |
| `--badbytes <hex>` | Set bytes which should not be contained in gadgets |
| `-i, --info` | Show file header information (ELF/PE/Mach-O) |
| `-s, --sections` | Show file sections [ELF/PE/Mach-O] |
| `--opcode <hex>` | Search for opcodes (e.g., `ffe4` or `ffe?` or `ff??`) |
| `--string <str>` | Look for the string in all data sections |
| `--section <name>` | Print the data of this section |
| `--semantic <constraint>` | Semantic search for gadgets with constraints |
| `--instructions <instr>` | Search by instruction text (e.g., "jmp esp", "pop eax; ret") |

## Common Commands

### Scenario 1: Basic gadget search

```bash
# List all ROP gadgets in a binary
ropper -f vulnerable_binary

# List gadgets with a maximum of 5 instructions
ropper -f vulnerable_binary --inst-count 5

# Show binary information (NX, ASLR, etc.)
ropper -f vulnerable_binary -i
```

### Scenario 2: Search for specific gadgets

```bash
# Search for gadgets containing "pop rdi"
ropper -f vulnerable_binary --search "pop rdi"

# Search for syscall gadgets
ropper -f vulnerable_binary --type sys

# Search for JOP gadgets
ropper -f vulnerable_binary --type jop

# Search for exact opcode bytes
ropper -f vulnerable_binary --opcode "5fc3"
```

### Scenario 3: Filter bad characters

```bash
# Exclude gadgets containing null bytes and newlines
ropper -f vulnerable_binary --badbytes 000a0d

# Search specific gadgets while filtering bad bytes
ropper -f vulnerable_binary --search "pop rdi" --badbytes 000a0d
```

### Scenario 4: Automatic ROP chain generation

```bash
# Generate execve("/bin/sh") ROP chain (Linux x86/x86_64)
ropper -f vulnerable_binary --chain execve

# Generate mprotect ROP chain with address and size
ropper -f vulnerable_binary --chain "mprotect address=0xdeadbeef size=0x10000"

# Generate VirtualProtect ROP chain (Windows x86)
ropper -f vulnerable_binary --chain "virtualprotect address=0xdeadbeef"
```

### Scenario 5: Custom base address and architecture

```bash
# Analyze with custom image base
ropper -f shellcode.bin -I 0x08048000

# Specify architecture for raw binaries
ropper -f firmware.bin --arch ARM

# Search across all gadget types
ropper -f vulnerable_binary --type all
```

## Notes & Tips

1. Use `--inst-count` to limit gadget length — shorter gadgets are more reliable and easier to chain.
2. Always filter with `--badbytes` when developing exploits for protocols that restrict certain byte values (e.g., `00` for null-terminated strings, `0a` for newlines).
3. Automatic chain generation (`--chain`) requires sufficient gadgets in the binary — use larger binaries or shared libraries (libc) if the target binary is too small.
4. ropper supports an interactive mode — run `ropper --console` and use the `file` command to load binaries within the shell.
5. For large binaries, initial gadget enumeration can take significant time — use `--section .text` to limit the search scope.

---

## Official References

- [Ropper (GitHub)](https://github.com/sashs/Ropper)
- [ropper — Kali Tools](https://www.kali.org/tools/ropper/)
