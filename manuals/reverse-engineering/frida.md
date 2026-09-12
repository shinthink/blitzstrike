# Frida

- **Category**: Reverse Engineering / Runtime Instrumentation
- **Risk Level**: 🔴 High

---

## Description

Dynamic instrumentation toolkit for injecting JavaScript into running processes. In mobile assessments, use it to inspect runtime behavior, bypass SSL pinning/root checks, hook crypto functions, and extract runtime secrets when authorized.

## Installation

```bash
pipx install frida-tools
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-U` / `--usb` | Connect to USB device |
| `-D <id>` / `--device` | Connect to device with the given ID |
| `-R` / `--remote` | Connect to remote frida-server |
| `-H <host>` / `--host` | Connect to remote frida-server on HOST |
| `-f <target>` / `--file` | Spawn target application |
| `-F` / `--attach-frontmost` | Attach to frontmost application |
| `-n <name>` / `--attach-name` | Attach by process name |
| `-N <id>` / `--attach-identifier` | Attach by application identifier |
| `-p <pid>` / `--attach-pid` | Attach by PID |
| `-W <pattern>` / `--await` | Await spawn matching PATTERN |
| `-l <script>` / `--load` | Load JavaScript hook script |
| `-e <code>` / `--eval` | Evaluate JavaScript code directly |
| `-c <uri>` / `--codeshare` | Load a Frida CodeShare script |
| `-C <cmodule>` / `--cmodule` | Load a C module |
| `-P <json>` / `--parameters` | Parameters as JSON (same as Gadget) |
| `--pause` | Leave main thread paused after spawning |
| `-q` | Quiet mode (no prompt), quit after `-l` and `-e` |
| `-t <sec>` / `--timeout` | Seconds to wait before terminating in quiet mode |
| `-o <file>` / `--output` | Output to log file |
| `--runtime {qjs,v8}` | Script runtime to use |
| `--kill-on-exit` | Kill the spawned program when Frida exits |
| `--auto-perform` | Wrap entered code with Java.perform |
| `--token <token>` | Authenticate with HOST using TOKEN |
| `--certificate <cert>` | Speak TLS with HOST, expecting CERTIFICATE |

## Common Commands

```bash
# List USB device processes
frida-ps -Uai

# Spawn Android app with hook (default: resumes automatically)
frida -U -f <package.name> -l ssl-bypass.js

# Attach to running process
frida -U -n <process-name> -l hook.js
```

## Notes & Tips

1. Requires a matching `frida-server` on Android or a supported iOS setup.
2. Runtime hooks can alter app behavior; confirm explicit authorization before bypassing controls.
3. Preserve hook scripts and app/device versions as evidence.

---

## Official References

- [Frida Documentation](https://frida.re/docs/home/)
- [frida-tools GitHub](https://github.com/frida/frida-tools)

