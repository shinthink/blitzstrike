# Ghidra Headless

- **Category**: Reverse Engineering / Binary Analysis
- **Risk Level**: 🟡 Medium

---

## Description

Ghidra's `analyzeHeadless` CLI runs imports, analysis, and scripts without the GUI. Use it only for targeted binary analysis tasks with a clear question and bounded runtime.

## Installation

```bash
sudo apt install ghidra
/usr/share/ghidra/support/analyzeHeadless
```

> **Note**: The headless binary is located at `/usr/share/ghidra/support/analyzeHeadless`. There is no `analyzeHeadless` in `$PATH` by default on Kali; use the full path or create a symlink.

## Parameter Reference

| Parameter | Description |
|------|------|
| `<project_location> <project_name>[/<folder_path>]` | Headless project location and name (required) |
| `-import [<directory>\|<file>]+` | Import one or more files or directories |
| `-process [<project_file>]` | Process an already-imported file in the project |
| `-preScript <ScriptName>` | Run script before analysis |
| `-postScript <ScriptName>` | Run script after analysis |
| `-scriptPath "<path1>[;<path2>...]"` | Semi-colon separated script directories |
| `-propertiesPath "<path1>[;<path2>...]"` | Semi-colon separated properties directories |
| `-scriptlog <path>` | Path to script log file |
| `-log <path>` | Path to log file |
| `-overwrite` | Overwrite existing project files on import |
| `-recursive` | Recursively import directories |
| `-readOnly` | Do not save changes to the project |
| `-deleteProject` | Delete project after run |
| `-noanalysis` | Import without running auto-analysis |
| `-processor <languageID>` | Specify processor/language ID |
| `-cspec <compilerSpecID>` | Specify compiler spec ID |
| `-analysisTimeoutPerFile <seconds>` | Limit analysis time per file |
| `-max-cpu <cores>` | Maximum CPU cores to use |
| `-loader <loader name>` | Specify desired loader |
| `-mirror` | Mirror remote repository locally |
| `-keystore <KeystorePath>` | Keystore path for server connections |
| `-connect [<userID>]` | Connect to Ghidra Server |
| `-librarySearchPaths <path1>[;<path2>...]` | Library search paths |

## Common Commands

```bash
# Import and analyze one binary with timeout
/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj target_proj \
  -import /usr/bin/target -analysisTimeoutPerFile 120

# Run a post-analysis script
/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj target_proj \
  -import /usr/bin/target \
  -scriptPath /tmp/ghidra_scripts -postScript ExportFunctions.java -deleteProject

# Process an already-imported binary without re-importing
/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj target_proj \
  -process target_binary -readOnly -postScript ListFunctions.java

# Import recursively from a directory, no analysis
/usr/share/ghidra/support/analyzeHeadless /tmp/ghidra_proj target_proj \
  -import /tmp/samples/ -recursive -noanalysis
```

## Notes & Tips

1. Do not use Ghidra GUI workflows in this skill.
2. Headless analysis can be slow; reserve it for a few high-value binaries.
3. Prefer `strings`, `readelf`, `objdump`, `rabin2`, and `radare2` first for quick triage.

---

## Official References

- [Ghidra GitHub](https://github.com/NationalSecurityAgency/ghidra)

