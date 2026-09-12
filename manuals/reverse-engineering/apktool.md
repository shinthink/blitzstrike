# Apktool

- **Category**: Reverse Engineering / Android Decompilation
- **Risk Level**: 🟢 Low

---

## Description

Android APK reverse-engineering utility for decoding resources, AndroidManifest.xml, smali code, certificates, and packaged assets. Use it for static mobile app review, not for redistributing modified apps.

## Installation

```bash
apt-get update && apt-get install -y apktool
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `d[ecode] <apk>` | Decode APK |
| `b[uild] <dir>` | Build decoded project |
| `if`, `install-framework <apk>` | Install framework file |
| `-o, --output <path>` | Output folder name (default: apk.out) for decode, or output APK name for build |
| `-f, --force` | (decode) Force delete destination directory |
| `-f, --force-all` | (build) Skip changes detection and build all files |
| `-r, --no-res` | Do not decode resources |
| `-s, --no-src` | Do not decode sources/smali |
| `-p, --frame-path <dir>` | Framework files directory |
| `-t, --frame-tag <tag>` | Tag for framework files (decode) |

## Common Commands

```bash
# Decode APK
apktool d app.apk -o /tmp/app_apktool

# Extract manifest-relevant data
grep -R "android:debuggable\\|android:allowBackup\\|android:exported" /tmp/app_apktool/AndroidManifest.xml

# Search decoded resources for endpoints and secrets
grep -RniE "api_key|secret|https?://" /tmp/app_apktool/res /tmp/app_apktool/assets
```

## Notes & Tips

1. Review `AndroidManifest.xml` for `debuggable`, `allowBackup`, exported components, custom permissions, and cleartext traffic settings.
2. Smali output is useful for targeted string and API endpoint searches even when Java decompilation fails.
3. Do not rebuild/sign/install modified apps unless runtime tampering is authorized.

---

## Official References

- [Apktool CLI Parameters](https://apktool.org/docs/cli-parameters/)
- [Apktool GitHub](https://github.com/iBotPeaches/Apktool)
