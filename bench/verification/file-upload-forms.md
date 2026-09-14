# Verification: unrestricted file upload (forms plugin)

- **Detector:** `file_upload` → `detectFileUploadRce`
- **Target:** a forms plugin (PHP), vulnerable release
- **Ground truth:** CVE-2026-15748 — an AJAX upload handler writes an attacker-named
  file without a server-side extension whitelist → RCE.
- **Result:** TP — `file_upload @ upload.php` (the `move_uploaded_file` sink).

## Evidence

The `wp_ajax_nopriv_*` handler reads `$_FILES` and calls `move_uploaded_file` to an
attacker-influenced path, with no extension/mime whitelist in scope.

## Notes

- Class-method handler resolution was required first: the handler is registered as
  `array($this, 'save_entry')`, so a string-only handler regex would miss it.
