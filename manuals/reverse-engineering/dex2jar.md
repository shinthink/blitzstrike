# dex2jar

- **Category**: Reverse Engineering / Android
- **Risk Level**: 🟢 Low

---

## Description

dex2jar is a set of tools for converting Android DEX (Dalvik Executable) files to Java JAR files for static analysis. It can process APK files directly, extracting and converting the embedded `classes.dex`. The output JAR can then be examined with Java decompilers such as jadx or JD-GUI. Additional utilities handle JAR-to-DEX conversion, APK signing, and Jasmin assembly transformations. Part of the standard Android reverse engineering workflow: APK → dex2jar → JAR → decompiler.

## Installation

```bash
sudo apt install dex2jar
```

## Parameter Reference

### d2j-dex2jar

| Parameter | Description |
|-----------|-------------|
| `-f, --force` | Force overwrite existing output file |
| `-o, --output <file>` | Output JAR file path |
| `-nc, --no-code` | Skip code conversion, only convert structure |
| `-d, --debug-info` | Include debug information in output |
| `-r, --reuse-reg` | Reuse registers when possible (smaller output) |
| `-n, --not-handle-exception` | Do not handle exception conversion |
| `-e, --exception-file <file>` | Write exception details to file |

### Other Utilities

| Parameter | Description |
|-----------|-------------|
| `d2j-jar2dex` | Convert JAR file back to DEX format |
| `d2j-apk-sign` | Sign an APK file with a test certificate |
| `d2j-jar2jasmin` | Convert JAR to Jasmin assembly files |
| `d2j-jasmin2jar` | Convert Jasmin assembly files back to JAR |

## Common Commands

### Scenario 1: Convert APK to JAR

```bash
# Convert an APK directly to JAR for decompilation
d2j-dex2jar app.apk -o app-dex2jar.jar

# Force overwrite if output already exists
d2j-dex2jar -f app.apk -o app-dex2jar.jar
```

### Scenario 2: Convert extracted DEX file

```bash
# Extract classes.dex from APK manually, then convert
unzip app.apk classes.dex
d2j-dex2jar classes.dex -o classes-dex2jar.jar

# Convert with debug info preserved
d2j-dex2jar -d classes.dex -o classes-debug.jar
```

### Scenario 3: Structure-only conversion

```bash
# Convert without code (class/method signatures only)
d2j-dex2jar --no-code app.apk -o app-structure.jar
```

### Scenario 4: Reverse conversion and signing

```bash
# Convert a modified JAR back to DEX
d2j-jar2dex modified.jar -o classes.dex

# Sign a repackaged APK with a test certificate
d2j-apk-sign unsigned.apk -o signed.apk
```

### Scenario 5: Jasmin assembly workflow

```bash
# Disassemble JAR to Jasmin assembly for manual editing
d2j-jar2jasmin app.jar -o jasmin_output/

# Reassemble edited Jasmin files back to JAR
d2j-jasmin2jar jasmin_output/ -o modified.jar
```

## Notes & Tips

1. dex2jar is a conversion tool, not a decompiler — pair it with jadx, JD-GUI, or Procyon to read the resulting Java source.
2. For multi-DEX APKs (`classes.dex`, `classes2.dex`, etc.), convert each DEX file separately or use jadx which handles multi-DEX natively.
3. Conversion errors are common with heavily obfuscated APKs — use `-e error.log` to capture exceptions for troubleshooting.
4. The `d2j-apk-sign` utility uses a test certificate only suitable for analysis workflows, not production signing.
5. Consider using jadx directly as a more modern alternative that converts DEX to Java source without the intermediate JAR step.

---

## Official References

- [dex2jar (GitHub)](https://github.com/pxb1988/dex2jar)
- [dex2jar — Kali Tools](https://www.kali.org/tools/dex2jar/)
