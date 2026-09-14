# Verification: unrestricted file upload (extension not whitelisted)

- **Detector:** `file_upload` → `detectFileUploadRce`
- **Target:** a contact-form plugin (PHP), vulnerable release
- **Ground truth:** CVE-2020-35489 — an uploaded file's name/extension is not
  whitelisted server-side, so a `.php` file lands web-reachable → RCE.
- **Result:** TP — `file_upload @ file.php` (the `move_uploaded_file` sink).

## Evidence

`move_uploaded_file($tmp_name, $new_file)` writes an attacker-named file with no
filetype/extension whitelist in scope.

## Notes

- The patched release has the SAME sink (the extension whitelist lives cross-file),
  so a per-file detector flags both — the remaining 1 FP is an inherent per-file
  limitation (documented in the FP corpus).
