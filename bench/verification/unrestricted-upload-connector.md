# Verification: unrestricted upload (file-manager connector config)

- **Detector:** `file_upload` → `detectUnrestrictedUpload`
- **Target:** a file-manager plugin's bundled connector (PHP)
- **Ground truth:** CVE-2020-25213 — the connector config sets
  `'uploadAllow' => array('all')` with `'uploadOrder' => array('deny','allow')`,
  so the allow list overrides the deny list → any mimetype uploadable → RCE.
- **Result:** TP — `file_upload @ connector.minimal.php:157`.

## Evidence

The config line `'uploadAllow'=>array('all')` combined with the deny→allow order is
the exact misconfiguration the detector targets.

## Notes

- This is a CONFIG-driven bug (not a source→sink taint), so it needed a dedicated
  config detector — the taint engine cannot see it.
- Enabling fix: `lib/` no longer skipped, so the bundled connector library is scanned.
