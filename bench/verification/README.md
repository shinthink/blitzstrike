# Verification corpus

"Battle-tested" is a claim, not a property — unless it is auditable. This directory
is the audit trail: every detector that was verified against a real vulnerable
target gets a writeup here, recording the detector, the target, the ground truth,
the result, and the evidence. A detector with no writeup here is unverified.

## Methodology (blind, deterministic)

1. **Ground truth first** — the target's vulnerability is established from its CVE
   (NVD cross-check), not from the detector's opinion.
2. **Blind scan** — the detector is pointed at the target's source directory only;
   it is never told where the bug is.
3. **Result** — TP (true positive: the detector surfaced the real sink) or FP
   (the detector fired on a clean target).

## Format

Each writeup records: `Detector` · `Target` · `Ground truth` · `Result` ·
`Evidence` · `Notes`.

## Verified detectors

| Detector | Target class | Result | Writeup |
|---|---|---|---|
| priv_esc (cross-file) | membership plugin role change | TP | [priv-esc](priv-esc-role-change.md) |
| file_upload (unrestricted) | file-manager connector config | TP | [unrestricted-upload](unrestricted-upload-connector.md) |
| file_upload (extension) | contact-form plugin | TP | [file-upload-ext](file-upload-extension.md) |
| file_upload (upload RCE) | forms plugin | TP | [file-upload-forms](file-upload-forms.md) |
| sql_injection (cross-file) | e-commerce plugin | TP | [sqli-cross-file](sqli-cross-file.md) |

## FP corpus

Separately, `../fp-test/` holds 19 clean/latest plugins scanned to measure the
false-positive rate; `detectFileUploadRce` was tuned there (removed the WP-safe
`wp_handle_upload` sink, added comment-only stripping) from 6 → 2 FPs.
