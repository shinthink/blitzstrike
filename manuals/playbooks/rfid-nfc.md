# RFID/NFC & Hardware Access Playbook

Use for authorized RFID/NFC, Proxmark3, PC/SC smart-card, token, physical credential, embedded device, or USB security assessment.

## Inputs

- Authorized card/token types, reader hardware, physical location, and custody rules.
- Allowed actions: identify, read, dump, key test, emulate, clone, write, or APDU testing.
- Safety limits for write operations, destructive tests, and credential handling.
- Scope clarification: whether firmware extraction, embedded device testing, or USB assessment is included.

## Environment

- Use a physical Kali host or VM with direct USB reader access.
- Do not use Docker unless the reader is already passed through and verified.
- Default to read-only actions until explicit approval is confirmed.

## Workflow

1. **Reader and card inventory**
   - Identify readers, card type, UID/ATR, frequency, and protocol.
   - Use `proxmark3`, `libnfc` tools, `opensc-tool`, or `pkcs15-tool` depending on hardware.

   (See `../rfid-nfc/README.md` for RFID/NFC tool selection.)

2. **Read-only collection**
   - Collect public metadata, certificates, ATR, tag type, and approved dumps.
   - Preserve raw dumps and command logs with chain-of-custody notes.

3. **Card type identification and strategy**
   - After inventory, determine card type and select appropriate testing strategy:
     - **MIFARE Classic** — `proxmark3 hf mf chk` for default keys, then `darkside` or `nested` attacks if authorized.
     - **HID iCLASS** — standard key testing with `proxmark3 hf iclass`.
     - **DESFire/EV1** — limited to read-only enumeration; encryption prevents key recovery without authorization.
     - **EM4100/T5577 (LF)** — `proxmark3 lf search` for identification, cloning assessment if authorized.
   - Use the decision tree below to select next steps:
     1. Card identified? If no, retry with `proxmark3 auto` or `nfc-list`.

   ```bash
   nfc-list                              # list NFC devices and nearby tags
   ```
     2. Default keys found? If yes, proceed to full read. If no, assess whether key recovery attacks are in scope.
     3. Write/clone authorized? If yes, proceed to Phase 6. If no, stop at read-only results.

   ```bash
   # Identify card type automatically
   pm3 -- auto
   # LF card search
   pm3 -- lf search
   # MIFARE Classic default key check
   pm3 -- hf mf chk --1k -f /usr/share/proxmark3/dictionaries/mfc_default_keys.dic
   # MIFARE Classic darkside attack (if default keys not found, authorization required)
   pm3 -- hf mf darkside
   # MIFARE Classic nested attack (requires at least one known key)
   pm3 -- hf mf nested --1k --blk 0 -a -k <known-key>
   # HID iCLASS standard key test
   pm3 -- hf iclass dump --ki 0
   # DESFire enumeration (read-only)
   pm3 -- hf mfdes info
   ```

4. **Controlled testing**
   - Run key checks, MIFARE tests, APDU scripts, emulation, cloning, or writes only when explicitly authorized.
   - Stop immediately on card errors, unexpected state changes, or reader instability.

   **Per-card-type key coverage:** Test default keys against EVERY card type identified in Phase 2, not just the first card found. For MIFARE Classic, run the full default key dictionary against all sectors (not just sector 0). If darkside or nested attacks are authorized, attempt them on every card that fails default key checks.
   - Proxmark3 key testing and emulation (authorized scope only):

   ```bash
   # MIFARE Classic — test default keys
   pm3 -- hf mf chk --1k -f /usr/share/proxmark3/dictionaries/mfc_default_keys.dic
   # MIFARE Classic — full read with known keys
   pm3 -- hf mf dump --1k
   # Emulate a saved card dump
   pm3 -- hf mf sim --1k -u <UID>
   ```

   - PC/SC APDU scripting with `opensc-tool` or `pcsc_scan` for smart card interaction:

   ```bash
   pcsc_scan                             # enumerate connected smart cards
   opensc-tool --send-apdu 00A4040000   # send raw APDU (SELECT)
   ```

   Use `scriptor` for interactive APDU command exchanges with smart cards (see `../rfid-nfc/tools/scriptor.md`).

   - Smart card certificate and key enumeration with `pkcs15-tool`:

   ```bash
   pkcs15-tool --list-certificates
   pkcs15-tool --list-keys
   ```

5. **Evidence handling**
   - Treat dumps, keys, certificates, and identifiers as sensitive data.
   - Report whether data was read-only, derived, cloned, or written.

6. **Replay and cloning assessment** (if explicitly authorized for write/clone operations)
   - Test whether captured card data can be replayed or cloned to a blank card.
   - Document whether the access control system detects duplicate card usage.
   - This phase demonstrates real-world physical security impact.

   ```bash
   # Clone MIFARE Classic dump to a blank card (write authorization required)
   pm3 -- hf mf restore --1k
   # Clone LF EM4100 ID to a T5577 card
   pm3 -- lf em 410x clone --id <card-id>
   # Test cloned card against access control system and document result
   ```

   Risk gate: Stop if the access control system triggers an alert on duplicate card usage. Document the detection capability as a positive security finding.

7. **Firmware and embedded device testing**
   - Perform only when in scope and with explicit authorization for physical device access.
   - Identify UART, JTAG, and SPI interfaces on device boards.
   - Extract firmware for offline analysis.
   - Note: this requires physical access to device boards and explicit authorization.

   ```bash
   # Identify UART/JTAG/SPI pinouts (manual hardware step, then connect)
   # Firmware extraction with flashrom (SPI flash)
   flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware_dump.bin
   # Firmware extraction/analysis with binwalk
   binwalk -e firmware_dump.bin
   # Search for hardcoded credentials and certificates
   strings firmware_dump.bin | grep -iE 'password|passwd|secret|key|cert'
   binwalk --signature firmware_dump.bin
   ```

   Risk gate: Do not write to flash or modify firmware unless explicitly authorized for destructive testing.

8. **USB/HID security assessment**
   - Perform only when in scope. Document USB port access controls.
   - Test whether USB mass storage is restricted on target systems.
   - Test whether USB HID devices are filtered or blocked.
   - Note: actual BadUSB payload testing requires dedicated tools not in the current tool inventory. This phase covers assessment and documentation only.

   ```bash
   # Check USB device enumeration
   lsusb
   # Check dmesg for USB device connection events
   dmesg | tail -20
   # Document USB policy (observe whether mass storage mounts automatically)
   ```

   Risk gate: Do not deploy USB attack payloads without explicit authorization and dedicated tooling.

## Cross-References

- `wireless-assessment.md` — Bluetooth proximity estimation for physical access correlation.
- `reporting-workflow.md` — evidence packaging and report generation.

## Expected Artifacts

- Reader model, card/token identifiers, protocol, frequency, and ATR/UID data.
- Card type classification and applicable attack strategy documentation.
- Command logs, approved dumps, hashes, and certificate metadata.
- Replay/cloning test results and access control detection assessment (if authorized).
- Firmware analysis findings: hardcoded credentials, certificates, interesting strings (if in scope).
- USB security posture notes (if in scope).
- Clear notes on read/write/clone/emulation actions performed or not performed.

## Stop When

- Authorized cards/tokens have been identified and tested to the approved depth.
- Card type strategy has been evaluated and documented.
- Further testing requires write, clone, emulation, destructive APDUs, or handling credentials beyond scope.
- Firmware or USB testing is complete or was not in scope.
