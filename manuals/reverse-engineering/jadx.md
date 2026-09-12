# JADX

- **Category**: Reverse Engineering / Android Decompilation
- **Risk Level**: 🟡 Medium

---

## Description

DEX to Java decompiler with CLI and GUI variants. Use the CLI for automated static analysis of APK, DEX, and AAR files to find insecure storage, hardcoded secrets, weak crypto, and API endpoints.

## Installation

```bash
apt-get update && apt-get install -y jadx
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d <dir>` | Output directory |
| `-ds <dir>` | Output directory for sources |
| `-dr <dir>` | Output directory for resources |
| `-r`, `--no-res` | Do not decode resources |
| `-s`, `--no-src` | Do not decompile source code |
| `-j <n>` | Processing threads count (default: 2) |
| `-e`, `--export-gradle` | Save as Gradle project |
| `-m <mode>` | Decompilation mode: `auto` (default), `restructure`, `simple`, `fallback` |
| `--single-class <name>` | Decompile a single class (full name, raw or alias) |
| `--output-format <fmt>` | Output format: `java` (default) or `json` |
| `--show-bad-code` | Show inconsistent decompiled code |
| `--no-debug-info` | Disable debug info parsing |
| `--no-imports` | Always write entire package name |
| `--deobf` | Activate deobfuscation |
| `--deobf-min <n>` | Min name length before renaming (default: 3) |
| `--deobf-max <n>` | Max name length before renaming (default: 64) |
| `--mappings-path <path>` | Deobfuscation mappings file (Tiny/Enigma format) |
| `--rename-flags <flags>` | Fix options: `case`, `valid`, `printable`, `none`, `all` (default) |
| `<input>` | Input files (.apk, .dex, .jar, .class, .smali, .zip, .aar, .aab) |

## Common Commands

```bash
# Decompile APK
jadx -d /tmp/app_jadx app.apk

# Decompile with deobfuscation
jadx --deobf -d /tmp/app_jadx app.apk

# Search for risky patterns
grep -RniE "SharedPreferences|MODE_WORLD_READABLE|http://|Log\\.(d|e|i)|TrustManager|HostnameVerifier" /tmp/app_jadx
```

## Notes & Tips

1. Use `jadx` for source-like logic review and `apktool` for manifest/resources/smali fidelity.
2. Decompiled output may be wrong for obfuscated or optimized code; validate critical findings with runtime tests.
3. Search for endpoints, tokens, weak crypto, debug logging, local storage, WebView settings, and TLS bypass code.

---

## Official References

- [jadx GitHub](https://github.com/skylot/jadx)

