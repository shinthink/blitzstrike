# Wireless Assessment Playbook

Use for authorized Wi-Fi, Bluetooth, or BLE testing with physical access and compatible wireless hardware.

## Inputs

- Authorized SSIDs/BSSIDs, Bluetooth device addresses, channels, physical location, and test window.
- Allowed techniques: passive capture, handshake capture, WPS testing, evil twin, deauthentication, Bluetooth/BLE enumeration, or BLE MITM.
- Wireless/Bluetooth adapter model and monitor-mode or BLE support.

## Environment

- Use physical or VM Kali with direct access to the wireless or Bluetooth adapter.
- Do not use Docker for monitor mode, packet injection, or hardware-dependent Bluetooth/BLE testing unless hardware access has been verified.
- Confirm local legal authorization before transmitting frames or interacting with nearby Bluetooth devices.

## Workflow

1. **Adapter validation**
   - Check interface names, driver, monitor mode, and injection support.
   - Use `airmon-ng`, `iw`, and `airmon-ng check` as needed.
   - Kill interfering processes before enabling monitor mode.

   (See `../wireless/README.md` for wireless tool selection.)

   ```bash
   iw dev                                                   # list wireless interfaces
   airmon-ng check                                          # check for interfering processes
   airmon-ng check kill                                     # kill interfering processes
   airmon-ng start wlan0                                    # enable monitor mode
   aireplay-ng -9 wlan0mon                                  # injection test
   ```

2. **Passive discovery**
   - Use `airodump-ng`, `kismet`, or `wash` to identify authorized SSIDs/BSSIDs, channels, encryption, clients, and WPS state.

   ```bash
   airodump-ng wlan0mon --band abg -w /tmp/wifi_scan --output-format csv
   wash -i wlan0mon -o /tmp/wps_targets.csv                 # WPS-enabled APs
   ```

3. **Capture**
   - Capture handshakes or PMKID with `airodump-ng`, `hcxtools`, or compatible tools.
   - Avoid deauthentication unless explicitly authorized.

   **Per-network capture coverage:** Attempt handshake or PMKID capture for EVERY authorized network, not just the first one. Track each SSID/BSSID as: handshake captured, PMKID captured, capture failed (with reason), or skipped (out of scope). If passive capture fails after a reasonable wait, escalate to deauthentication only with explicit authorization.

   ```bash
   # Targeted capture (replace <ch> and <bssid> from discovery)
   airodump-ng -c <ch> --bssid <bssid> -w /tmp/handshake wlan0mon
   # PMKID capture (no clients needed; filter post-capture with hcxpcapngtool)
   hcxdumptool -i wlan0mon -o /tmp/pmkid.pcapng
   # Deauth (only if authorized)
   aireplay-ng -0 5 -a <bssid> -c <client> wlan0mon
   ```

4. **WPS testing**
   - Use `reaver` or `bully` only against authorized WPS-enabled targets.

   ```bash
   reaver -i wlan0mon -b <bssid> -vv
   bully wlan0mon -b <bssid> -v 3
   ```

   **Per-target WPS coverage:** Test ALL WPS-enabled targets identified in Phase 2, not just the first. Track each target as: WPS PIN recovered, Pixie Dust attempted (`reaver -K` or `pixiewps`), brute-force attempted, or WPS locked out. Include `pixiewps` for offline Pixie Dust attacks when the exchange is captured.

5. **Cracking and validation**
   - Use `aircrack-ng`, `hashcat`, or `john` with approved wordlists and time budgets. Use `cowpatty` as a CPU-based fallback when `hashcat` GPU acceleration is unavailable.
   - Record whether cracking succeeded and avoid connecting to networks unless authorized.

   (See `../password/README.md` for cracking tool selection.)
   - **WPA3/SAE awareness**: If WPA3 is detected, document the protection level and focus on other attack vectors: implementation flaws, transition mode downgrade (WPA3-Transition allows WPA2 fallback — attempt downgrade capture), and client misconfiguration. See `password-audit.md` for extended cracking strategies.

   ```bash
   aircrack-ng -w /usr/share/wordlists/rockyou.txt /tmp/handshake*.cap
   hcxpcapngtool -o /tmp/hash.hc22000 /tmp/pmkid.pcapng     # convert PMKID to hashcat format
   hashcat -m 22000 /tmp/hash.hc22000 /usr/share/wordlists/rockyou.txt
   ```

6. **Advanced attacks**

   Advanced wireless attacks require explicit approval and an isolated test environment. Coordinate with the engagement lead before proceeding.

   6a. **Evil Twin / Rogue AP**
   - Set up a rogue AP mimicking the target network to test client behavior.
   - Use `hostapd` or `wifiphisher` (see `../wireless/tools/wifiphisher.md`) to create the rogue AP with a captive portal.
   - Capture credentials from clients that connect to the rogue AP.
   - Monitor for automatic client association: note which devices connect without user interaction.
   - Risk gate: requires explicit authorization and an isolated test environment to avoid impacting production users.

   ```bash
   # Basic rogue AP with hostapd (requires hostapd.conf)
   hostapd /tmp/hostapd_evil.conf
   # Automated evil twin with captive portal
   wifiphisher -eI wlan0 -aI wlan1 -e "<target_ssid>" -p firmware-upgrade
   # Rogue AP with wifipumpkin3 (set ESSID inside the console or via -x)
   wifipumpkin3 -i wlan0 -x "set essid <target_ssid>; start"
   ```

   Use `wifipumpkin3` for rogue AP creation with built-in credential capture and traffic interception (see `../wireless/tools/wifipumpkin3.md`).

   6b. **WPA Enterprise (802.1X) testing**
   - If enterprise wireless (WPA2/WPA3-Enterprise, 802.1X) is detected: test PEAP/EAP-TTLS with a rogue RADIUS server to capture credentials from clients connecting to the evil twin.
   - Test certificate validation on supplicants — many clients accept untrusted certificates without warning.
   - This is critical for corporate environments where credential capture can lead to domain compromise.
   - Methodology: deploy a rogue AP with the target ESSID and a RADIUS server configured to accept all identities; capture EAP handshakes and relay or crack credentials.
   - Tools: `hostapd-mana` and `eaphammer` — see tool docs at `../wireless/tools/hostapd-mana.md` and `../wireless/tools/eaphammer.md` for installation and usage.
   - For cracking captured LEAP credentials, use `asleap` (see `../wireless/tools/asleap.md`):

     ```bash
     asleap -r /tmp/leap_capture.pcap -W /usr/share/wordlists/rockyou.txt
     ```

   6c. **Client-side attacks**
   - KARMA-style attacks: configure the rogue AP to respond to all probe requests, capturing clients searching for known networks.
   - Test known-network association behavior — determine if clients auto-connect to open networks they have previously joined.
   - Assess client isolation on the target network: can connected clients reach each other? Test ARP and direct IP communication between wireless clients.
   - Document which client devices are vulnerable to rogue AP association.

7. **Bluetooth and BLE**
   - Use `bluetoothctl` for Bluetooth device discovery and `btscanner` for passive enumeration.
   - Use `sdptool` for service enumeration on older stacks; on modern kernels `bluetoothctl` is preferred over the deprecated `hcitool scan`.
   - Use `gatttool` for BLE GATT read/write checks only against authorized devices.
   - Use `crackle` only when approved captures are explicitly in scope.
   - **BLE security testing**: analyze advertising data for information leakage (device names, service UUIDs, manufacturer data). Enumerate GATT services and characteristics — look for sensitive characteristics (read/write without authentication, notification channels leaking data). Assess BLE pairing security: sniff pairing exchanges to evaluate the pairing method (Just Works, Passkey, Numeric Comparison) and determine if key material can be recovered. Analyze connection parameters (interval, latency, timeout) for stability and attack surface.

   ```bash
   bluetoothctl scan on                      # discover nearby Bluetooth devices
   bluetoothctl info <BD_ADDR>               # device details
   sdptool browse <BD_ADDR>                  # service records
   gatttool -b <BD_ADDR> --primary           # BLE GATT primary services
   gatttool -b <BD_ADDR> --characteristics   # enumerate all characteristics
   gatttool -b <BD_ADDR> --char-read -a <handle>  # read a specific characteristic
   ```

   **Per-device BLE coverage:** Enumerate ALL discovered Bluetooth/BLE devices within scope, not just a sample. For each device: record advertising data, enumerate GATT services, test read/write characteristics, and assess pairing security.

8. **Post-authentication testing**
   - After successfully connecting to a wireless network (using captured or cracked credentials with explicit authorization): perform network reconnaissance from the wireless segment.
   - Test segmentation between wireless and wired networks — can the wireless client reach servers, printers, management interfaces, or other VLANs?
   - Check for internal services accessible from the wireless segment: DNS, DHCP, file shares, internal web applications, databases, and management consoles.
   - Identify the wireless VLAN assignment and compare access controls against the wired network policy.
   - Cross-reference `internal-network.md` for full internal network assessment methodology once on the wireless segment.

   ```bash
   # After connecting to the target wireless network
   ip addr show                          # confirm IP assignment and subnet
   ip route                              # check routing and gateway
   nmap -sn <wireless_subnet>/24         # discover hosts on the wireless segment
   nmap -sV -p 21,22,80,443,445,3389 <gateway>  # test gateway/firewall services
   ```

## Cross-References

- `internal-network.md` — post-authentication network testing.
- `password-audit.md` — extended cracking techniques and wordlist strategies.
- `reporting-workflow.md` — findings documentation and report generation.

## Expected Artifacts

- Wireless survey summary.
- Capture files and handshake validation.
- WPS test results.
- Evil twin and rogue AP test results (client association logs, captured credentials).
- WPA Enterprise test results (certificate validation, EAP credential capture).
- Bluetooth/BLE device and service inventory when in scope.
- BLE GATT service and characteristic enumeration results.
- Cracking logs and password status.
- Post-authentication network reconnaissance results and segmentation findings.
- Hardware and location notes.

## Stop When

- Authorized networks have been surveyed and tested to the approved depth.
- Further work requires deauthentication, evil twin, phishing, BLE MITM, device writes, or credential use beyond the current authorization.
- Post-authentication testing has mapped the wireless segment — switch to `internal-network.md` for deeper internal assessment.
