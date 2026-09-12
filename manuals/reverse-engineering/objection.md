# objection

- **Category**: Reverse Engineering / Runtime Instrumentation
- **Risk Level**: 🔴 High

---

## Description

Frida-powered runtime mobile exploration toolkit. It provides high-level commands for Android and iOS SSL unpinning, storage inspection, Keystore/Keychain access, clipboard monitoring, and method hooking.

## Installation

```bash
pipx install objection
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-N`, `--network` | Connect to remote Frida server instead of USB |
| `-h`, `--host <addr>` | Frida server host (default: 127.0.0.1) |
| `-P`, `--port <port>` | Frida server port (default: 27042) |
| `-ah`, `--api-host <addr>` | API server host (default: 127.0.0.1) |
| `-ap`, `--api-port <port>` | API server port (default: 8888) |
| `-n`, `--name <app>` | Target package/bundle/process name |
| `-S`, `--serial <serial>` | Device serial to connect to |
| `-d`, `--debug` | Enable debug mode with verbose output |
| `-s`, `--spawn` | Spawn the target application instead of attaching |
| `-p`, `--no-pause` | Resume the target immediately after spawning |
| `-f`, `--foremost` | Use the current foremost application |
| `--debugger` | Enable the Chrome debug port |
| `--uid <uid>` | Specify the UID to run as (Android only) |

### Commands

| Command | Description |
|------|------|
| `start` | Start a new interactive session (primary subcommand) |
| `run <command>` | Execute a single objection command non-interactively |
| `api` | Start the objection API server in headless mode |
| `patchapk` | Patch an APK with frida-gadget.so |
| `patchipa` | Patch an IPA with the FridaGadget dylib |
| `signapk` | Zipalign and sign an APK with the objection key |
| `version` | Print the current version |

## Common Commands

```bash
# Android SSL pinning bypass
objection -n <package.name> start --startup-command "android sslpinning disable"

# Android root detection bypass
objection -n <package.name> start --startup-command "android root disable"

# Run a single command non-interactively
objection -n <package.name> run "ls"

# iOS Keychain dump
objection -n <bundle.id> run "ios keychain dump"

# Connect to remote Frida server
objection -N -h 192.168.1.100 -P 27042 -n <package.name> start

# Spawn app and resume immediately
objection -n <package.name> -s -p start

# Use foremost application
objection -f start

# Patch an APK with Frida gadget
objection patchapk -s app.apk

# Start API server in headless mode
objection -n <package.name> api
```

## Notes & Tips

1. `objection` is high-impact because it can bypass app controls and access sensitive local data.
2. Use the `run` subcommand for agent workflows to execute single commands non-interactively instead of long interactive sessions.
3. `explore` is a deprecated alias for `start`; both launch the interactive REPL. Use `start` for new workflows.
4. Use `-N` with `-h`/`-P` to connect to a remote Frida server over the network.
5. The `patchapk` command injects frida-gadget into an APK for non-rooted device testing.
6. Record device state, app version, command output, and whether bypasses changed behavior.

---

## Official References

- [Objection Documentation](https://github.com/sensepost/objection/wiki)
- [Objection GitHub](https://github.com/sensepost/objection)

