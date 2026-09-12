---
name: mobile-app-scan
description: Use when you need to check an iOS or Android app build for hardcoded secrets, insecure local storage, weak transport security, and exposed debug/backup surfaces. Covers static analysis of the built app package (APK/IPA); combine with web-app-pentest/api-security-test for the app's backend.
---

# Mobile app scan

## Prerequisites

- `MobSF` (Docker, handles both platforms, static + dynamic)
- `apktool` (Android decompilation, useful for manual follow-up beyond MobSF's report)

## Workflow

1. **Static analysis via MobSF** — covers most of this skill's checks in one pass:
   ```bash
   docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
   # upload the .apk or .ipa through the web UI at localhost:8000, or use the REST API:
   curl -F "file=@app.apk" http://localhost:8000/api/v1/upload
   curl -X POST http://localhost:8000/api/v1/scan -d "hash=<hash-from-upload>"
   curl -X POST http://localhost:8000/api/v1/report_json -d "hash=<hash-from-upload>" > findings/mobsf-report.json
   ```

2. **Manually confirm the highest-signal findings MobSF surfaces:**
   - **Hardcoded secrets** — API keys, credentials, or signing material embedded in strings/resources/BuildConfig. Grep decompiled source (`apktool d app.apk`) for `api_key`, `secret`, `password`, cloud credential patterns as a backstop if MobSF misses ecosystem-specific formats.
   - **Insecure local storage** — sensitive data (tokens, PII) written to `SharedPreferences`/`UserDefaults`/SQLite without encryption, or to world-readable file locations.
   - **Weak transport security** — certificate pinning absent (or present but trivially bypassable), `NSAllowsArbitraryLoads`/cleartext traffic permitted in the app manifest, TLS validation disabled or overly permissive (accepts self-signed/any cert).
   - **Debuggable / backup-enabled in release builds** — `android:debuggable="true"` or `android:allowBackup="true"` left on in a production APK exposes app data via `adb backup` or attaching a debugger to a real device.
   - **Exported components without protection** — Android `Activity`/`Service`/`BroadcastReceiver`/`ContentProvider` marked `exported="true"` without a permission check, reachable by any other app on the device.
   - **Client-side security logic** — any check that can be bypassed by an attacker fully controlling the client (root/jailbreak detection alone as a security boundary, business logic like "is this purchase valid" decided client-side instead of re-verified server-side).

3. **Root/jailbreak and tamper-detection review** — note presence/absence, but treat these as defense-in-depth, not a substitute for server-side validation of anything security-critical.

## Output

`findings/mobsf-report.json` plus manual notes. Report per finding: component/file, category (storage/transport/exported-surface/hardcoded-secret), severity, fix.

## Notes

- A backend API finding discovered through mobile reverse engineering (e.g., an endpoint only referenced in app code, never in the public web app) still belongs to `api-security-test` — flag it there once found.
- Dynamic analysis (MobSF's dynamic mode, instrumenting the app at runtime) gives higher-confidence results than static alone but requires an emulator/rooted device set up — use it when available, note when a finding is static-only and unconfirmed at runtime.
