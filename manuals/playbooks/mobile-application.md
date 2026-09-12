# Mobile Application Playbook

Use for authorized Android APKs, iOS IPAs, mobile API clients, or mobile runtime testing.

## Inputs

- APK/IPA files, package/bundle identifiers, app version, test account, and backend scope.
- Device/emulator type, root/jailbreak state, Frida/objection permission, and SSL pinning rules.
- Allowed runtime hooks, data extraction limits, and whether backend API testing is in scope.

## Workflow

1. **Scope and environment**
   - Confirm app ownership, allowed devices, accounts, and runtime instrumentation approval.
   - Record app hash, version, signing/certificate data, and device state.
   - Determine platform to select tool chain:

   (See `../reverse-engineering/README.md` for reverse engineering tool selection.)
     - Android: `apktool` (see `../reverse-engineering/tools/apktool.md`), `jadx` (see `../reverse-engineering/tools/jadx.md`), `objection` (see `../reverse-engineering/tools/objection.md`), `frida` (see `../reverse-engineering/tools/frida.md`), `adb`.
     - iOS: `otool`, `class-dump`, `objection`, `frida`, `codesign`.
   - Acquire the binary: use `adb pull` for installed Android apps or use provided APK/IPA files.

2. **Static analysis**
   - Use `apktool` for Android resources/manifests and `jadx` for Java-like source review.
   - Extract endpoints, secrets, debug flags, exported components, permissions, deeplinks, crypto use, and storage paths.
   - Decompile and search for hardcoded secrets:
     ```bash
     # Decompile APK to Java-like source with jadx
     jadx -d /tmp/app_jadx target.apk
     grep -RniE "api_key|secret|https?://|password" /tmp/app_jadx/
     ```
   - Check `AndroidManifest.xml` for security-relevant attributes:
     ```bash
     # Decode and inspect AndroidManifest.xml
     apktool d target.apk -o target_decoded
     grep -E 'android:debuggable|android:allowBackup|android:exported' target_decoded/AndroidManifest.xml
     ```
   - Identify exported activities, services, broadcast receivers, and content providers with `android:exported="true"` or intent filters without explicit `exported="false"`.
   - For iOS IPA files: unzip the IPA, inspect `Info.plist` for URL schemes, permissions, and ATS settings; check entitlements with `codesign -d --entitlements - <app.app>`; use `otool -l` for binary load commands and linked libraries; use `class-dump` or `objdump` for Objective-C class headers and symbol inspection.
   - Check `Info.plist` for ATS exceptions that weaken transport security:
     ```bash
     # Look for ATS exception domains and allowances
     plutil -p Payload/Target.app/Info.plist | grep -A5 'NSAppTransportSecurity'
     ```
   - Search for URL schemes registered in `CFBundleURLTypes`.

   **Static analysis completeness:** Check ALL exported components (activities, services, receivers, providers on Android; URL schemes on iOS), ALL permission declarations, and ALL hardcoded credential patterns. Do not stop at the first finding — enumerate the complete attack surface.

3. **Data storage security** (OWASP MASTG M9)
   - Check for sensitive data stored insecurely on the device.

   **Per-storage-location coverage:** Check ALL storage locations for each platform — not just the obvious ones. Android: SharedPreferences, SQLite databases, internal storage, external storage, backup files, and application logs. iOS: NSUserDefaults, Keychain, plist files, CoreData/SQLite, and application cache. Document each location as: contains sensitive data, clean, or not accessible.
   - Android — SharedPreferences, SQLite databases, internal/external storage:
     ```bash
     # List environment paths
     objection -n com.target.app run "env"

     # List SharedPreferences files
     objection -n com.target.app run "android sharedpreferences list"

     # Check SQLite databases for unencrypted PII
     objection -n com.target.app run "sqlite connect /data/data/com.target.app/databases/app.db"
     ```
   - iOS — NSUserDefaults, Keychain, application sandbox:
     ```bash
     # Dump Keychain entries for the app
     objection -n com.target.app run "ios keychain dump"

     # List environment paths in app sandbox
     objection -n com.target.app run "env"
     ```
   - Check for clipboard data leakage: hook `UIPasteboard` (iOS) or `ClipboardManager` (Android) to detect sensitive data copied to clipboard.
   - Inspect application log output for sensitive data leakage:
     ```bash
     # Filter logcat for target app output
     adb logcat --pid=$(adb shell pidof com.target.app) | tee /tmp/app_logcat.txt
     # Search logs for sensitive patterns
     grep -iE "token|password|secret|session|api_key" /tmp/app_logcat.txt
     ```
   - Verify screenshot/task-switcher leakage: check whether the app masks content on background or allows screenshots of sensitive screens.

4. **Network security** (OWASP MASTG M5)
   - Configure proxy for mobile traffic interception using `mitmproxy` (see `../web/tools/mitmproxy.md`):
     ```bash
     # Start mitmproxy on the test machine
     mitmproxy -p 8080

     # Android: set proxy via adb
     adb shell settings put global http_proxy <proxy_ip>:8080

     # Install mitmproxy CA on device
     # Android: push cert and install
     adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
     ```
   - Bypass certificate pinning with `objection`:
     ```bash
     # Android — SSL pinning bypass (persistent via startup command)
     objection -n com.target.app start --startup-command "android sslpinning disable"

     # iOS — SSL pinning bypass (persistent via startup command)
     objection -n com.target.app start --startup-command "ios sslpinning disable"
     ```
   - Detect cleartext traffic: search for `android:usesCleartextTraffic="true"` in AndroidManifest.xml; check for HTTP URLs in decompiled code.
   - Inspect WebView SSL handling for custom `TrustManager` or `onReceivedSslError` overrides that weaken certificate validation.

   **Per-endpoint network coverage:** Intercept and test ALL API endpoints the app communicates with, not just the first few. Build an endpoint inventory from intercepted traffic and verify authentication, authorization, and input validation on each.

5. **Runtime instrumentation**
   - Use `frida` and `objection` only on authorized devices/apps.
   - Android — list activities, services, and hook methods:
     ```bash
     # List activities and services
     objection -n com.target.app run "android hooking list activities"
     objection -n com.target.app run "android hooking list services"

     # Bypass root detection
     objection -n com.target.app run "android root disable"

     # Hook a specific class to monitor method calls
     objection -n com.target.app run "android hooking watch class com.target.app.AuthManager"

     # Hook a specific method with arguments and return value
     objection -n com.target.app run "android hooking watch class_method com.target.app.AuthManager.validateToken --dump-args --dump-return"
     ```
   - iOS — bypass jailbreak detection and inspect runtime:
     ```bash
     # Bypass jailbreak detection
     objection -n com.target.app run "ios jailbreak disable"

     # List classes and methods
     objection -n com.target.app run "ios hooking list classes"
     objection -n com.target.app run "ios hooking search classes Auth"
     ```
   - Frida script injection for advanced instrumentation:
     ```bash
     # SSL pinning bypass via Frida codeshare script
     frida -U -f com.target.app --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida

     # Attach to running process
     frida -U com.target.app -l hook_script.js
     ```
   - Test IPC mechanisms:
     - Android: deep links (`adb shell am start -d "scheme://path"`), intents, content providers (`content query --uri content://com.target.app.provider/`).
     - iOS: URL schemes (`xcrun simctl openurl booted "scheme://path"`), universal links.

6. **Binary protection assessment**
   - Android — check obfuscation and anti-tampering:
     ```bash
     # Check for ProGuard/R8 obfuscation in decompiled source
     # Obfuscated code shows single-letter class/method names
     ls target_decoded/smali/*/a/a/

     # Verify if app detects repackaging
     apktool b target_decoded -o repackaged.apk
     jarsigner -verbose -keystore test.keystore repackaged.apk alias_name
     adb install repackaged.apk
     ```
   - iOS — check binary protections:
     ```bash
     # Check for encryption (FairPlay)
     otool -l Payload/Target.app/Target | grep -A4 LC_ENCRYPTION_INFO

     # Check for Swift/ObjC symbol stripping
     nm Payload/Target.app/Target | head -20
     ```
   - Evaluate root/jailbreak detection effectiveness: test bypass with `objection` (`android root disable` / `ios jailbreak disable`) and assess if additional checks exist.
   - Check whether the app is debuggable and whether anti-debugging mechanisms are present.

7. **Backend API and reporting**
   - Build an endpoint list from static strings and runtime traffic.
   - Switch to `api-security.md` and `web-application.md` for backend API and HTTP testing.
   - Consolidate findings by OWASP MASTG category and include reproduction steps, affected versions, and evidence.

## Cross-References

- `api-security.md` — backend API testing.
- `web-application.md` — backend web testing.
- `reporting-workflow.md` — findings documentation.

## Expected Artifacts

- App hashes, version, signing/certificate metadata, and device state.
- Static findings with file/class/function references.
- Data storage audit: insecure storage locations and sensitive data found.
- Network capture: intercepted requests, pinning bypass evidence, cleartext findings.
- Runtime hook commands, IPC test results, and storage findings.
- Binary protection assessment: obfuscation level, detection bypass results.
- Endpoint inventory and captured request samples.

## Stop When

- Static analysis has covered: manifest/plist inspection, hardcoded secret search, exported component review, and binary protection assessment.
- Runtime checks have covered: data storage security, network interception with pinning bypass, IPC testing, and root/jailbreak detection bypass.
- Backend endpoints have been inventoried and handed off to `api-security.md` or `web-application.md`.
- Further testing requires bypassing controls, extracting user data, or attacking backend services beyond scope.
