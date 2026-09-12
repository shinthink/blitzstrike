# Specialized Protocols Playbook

Use for authorized VoIP, SIP/IAX, voice VLAN, ICS/OT, PLC, Modbus, IPMI/BMC, or other high-sensitivity protocol testing.

## Inputs

- Exact IPs, ports, protocols, device types, maintenance windows, and owner contacts.
- No-write rules, call/registration limits, lockout policy, and maximum request rates.
- Whether passive review, discovery, read-only validation, or active testing is authorized.
- OT safety classification for every target device (if ICS/OT is in scope).
- Physical access requirements and authorization for VLAN hopping or local switch-port tests.

## Workflow

### Decision Tree

After completing Phase 1, follow the branches that match discovered protocols:

- **SIP/IAX detected** on any host → Phase 2 (VoIP Discovery) → Phase 3 (VoIP Security Testing)
- **Modbus/S7/BACnet/DNP3 detected** on any host → Phase 4 (ICS/OT Discovery) → Phase 5 (ICS/OT Read-Only Assessment)
- **IPMI/SNMP/printer management detected** on any host → Phase 6 (IPMI/BMC and Network Infrastructure)
- **Layer 2 testing authorized** → Phase 7 (Layer 2 Protocol Testing)
- **All findings** → Phase 8 (Evidence, Risk Assessment, and Escalation)

Multiple branches may apply. For example, a site with both VoIP and ICS devices should complete Phases 2-3 and Phases 4-5 before proceeding to Phase 8. Always finish with Phase 8.

---

1. **Phase 1: Safety, Scope, and Protocol Inventory**

   Confirm authorization and identify which specialized protocols are present before any active testing begins.

   - Verify the authorized scope document lists every target IP, port, and protocol. Confirm stop conditions, maintenance windows, and emergency contacts for each device owner.
   - Review the criticality level of each device. OT/ICS devices connected to physical processes are safety-critical. VoIP infrastructure may be business-critical. Classify every target as safety-critical, business-critical, or standard before proceeding.
   - Prefer passive methods first: review existing network diagrams, tap captures, SPAN port data, and asset inventories from the client.
   - Run service detection with ICS and VoIP NSE scripts to identify specialized protocols across the authorized range. Use conservative timing to avoid disrupting fragile devices.

   ```bash
   # Service detection with specialized protocol scripts (conservative timing)
   nmap -sV -sC --script "sip-methods,sip-enum-users" -p 5060,5061 -T3 -oA /tmp/sip_scan <target-range>

   # ICS/OT protocol discovery
   nmap -sV --script "modbus-discover,s7-info" -p 102,502 -T2 -oA /tmp/ics_tcp_scan <ot-range>
   nmap -sV -sU --script bacnet-info -p 47808 -T2 -oA /tmp/bacnet_scan <ot-range>

   # Broad service scan for IPMI, SNMP, and management interfaces
   nmap -sV -sU -p 161,623,1900 -T3 -oA /tmp/mgmt_scan <target-range>
   ```

   For initial network discovery and host enumeration, see [Internal Network Playbook](internal-network.md) Phases 1-3.

   Risk gate: Do not proceed to any active testing phase until the scope document is confirmed and device criticality is classified. If any device is marked safety-critical, confirm that the OT owner has approved active scanning of that specific device.

2. **Phase 2: VoIP Discovery and Enumeration**

   Discover and enumerate SIP and IAX services within authorized scope.

   (See `../voip-ics/README.md` for VoIP/ICS tool selection.)

   - **SIP device discovery**: Use `svmap` to identify SIP-enabled devices across the target range. Specify the SIP port and keep request rates within authorized limits.
   - **SIP extension enumeration**: Once SIP hosts are identified, use `svwar` to enumerate valid extensions. Use a dictionary of common extension ranges or a targeted list provided by the client.
   - **SIP registration testing**: Check which extensions accept registration attempts. This reveals extensions that may have weak or default credentials.
   - **IAX enumeration**: If Asterisk IAX2 services are found (UDP/4569), use `enumiax` to enumerate IAX usernames.

   ```bash
   # SIP host discovery across subnet
   svmap <target-range> -p 5060

   # Enumerate SIP extensions on discovered host
   svwar -e 100-999 <sip-host> -m REGISTER

   # Enumerate SIP extensions with dictionary
   svwar -d /usr/share/wordlists/sipvicious/extensions.txt <sip-host>

   # SIP scanning and extension enumeration with sippts
   sippts scan -i <target-ip> -r 5060-5080
   sippts exten -i <target-ip> -e 100-999

   # IAX username enumeration on Asterisk targets
   enumiax -d /usr/share/wordlists/metasploit/unix_users.txt <iax-host>
   ```

   See `../voip-ics/tools/sipvicious.md` for `svmap`/`svwar`/`svcrack` parameter details, `../voip-ics/tools/sippts.md` for SIP Pentest Tools Suite options, and `../voip-ics/tools/enumiax.md` for IAX enumeration options.

   Decision point: If SIP extensions are found with registration capabilities, proceed to Phase 3 for security testing. If only passive SIP services are found (e.g., trunks with no user registration), document findings and skip to Phase 8.

3. **Phase 3: VoIP Security Testing**

   Test VoIP authentication, VLAN segregation, and media encryption. This phase requires explicit approval for credential attacks.

   **Per-service coverage:** Test ALL discovered SIP hosts and extensions, not just the first one. For each SIP host: verify authentication strength, check TLS vs. unencrypted signaling, and assess RTP encryption. For VLAN hopping, test every switch port with local access, not just one. Document each host × test as pass/fail/skipped.

   - **SIP authentication testing**: Use `svcrack` to test SIP credentials on discovered extensions. Start with default/common passwords. Full brute force requires explicit written approval and must respect lockout policies.
   - **Voice VLAN hopping**: Use `voiphopper` to test whether an attacker on the data VLAN can hop into the voice VLAN. This requires authorized local switch-port access. Test CDP, LLDP-MED, and DHCP-based VLAN discovery.
   - **RTP stream analysis**: If packet captures are available, check whether voice media uses SRTP (encrypted) or plain RTP (unencrypted). Unencrypted RTP allows eavesdropping on calls.
   - **SIP TLS verification**: Check whether SIP signaling uses TLS (port 5061) or unencrypted UDP/TCP (port 5060). Unencrypted SIP exposes credentials and call metadata.

   ```bash
   # SIP credential testing on a specific extension (requires approval)
   svcrack -u <extension> -d /usr/share/wordlists/rockyou.txt <sip-host> -p 5060

   # Voice VLAN discovery via CDP sniffing
   voiphopper -i eth0 -c 0

   # Voice VLAN hop after discovering VLAN ID
   voiphopper -i eth0 -v <vlan-id>

   # Check for unencrypted RTP in a capture file
   tshark -r /tmp/voip_capture.pcap -Y "rtp" -T fields -e rtp.ssrc -e rtp.p_type | head -20

   # Check SIP over TLS
   nmap -sV -p 5061 --script ssl-enum-ciphers <sip-host>
   ```

   See `../voip-ics/tools/sipvicious.md` for `svcrack` options, `../voip-ics/tools/voiphopper.md` for VLAN hopping modes, and `../forensics/tools/tshark.md` for packet analysis.

   For deeper credential testing workflows, see [Password Audit Playbook](password-audit.md).

   Risk gate: SIP credential brute force requires explicit written approval. VLAN hopping requires authorized local switch-port access. Stop immediately if any production call is disrupted or if the PBX shows signs of instability.

4. **Phase 4: ICS/OT Discovery**

   Identify ICS/OT devices and protocols. Classify every discovered device by safety criticality before any interaction beyond passive scanning.

   - **Modbus discovery**: Scan for Modbus services on TCP/502 using nmap NSE scripts and `plcscan`. Identify device types, firmware versions, and Modbus unit IDs.
   - **S7comm enumeration**: Scan for Siemens S7 PLCs on TCP/102. The `s7-info` NSE script retrieves module type, serial number, firmware version, and plant identification.
   - **BACnet discovery**: Scan for BACnet/IP devices on UDP/47808. The `bacnet-info` NSE script retrieves device instance, firmware, application software version, and object name.
   - **DNP3 identification**: Scan for DNP3 services on TCP/20000. Identify DNP3 outstations by their source and destination addresses.
   - **Device classification**: After discovery, classify every device into one of three categories before proceeding: (a) safety-critical (connected to physical processes that could cause harm), (b) monitoring-only (historians, HMIs displaying data), (c) IT-adjacent (engineering workstations, jump hosts).

   ```bash
   # Modbus device discovery
   nmap -sV --script modbus-discover -p 502 -T2 -oA /tmp/modbus_scan <ot-range>

   # Siemens S7 PLC enumeration
   nmap -sV --script s7-info -p 102 -T2 -oA /tmp/s7_scan <ot-range>

   # BACnet device discovery
   nmap -sV -sU --script bacnet-info -p 47808 -T2 -oA /tmp/bacnet_scan <ot-range>

   # DNP3 service identification
   nmap -sV -p 20000 -T2 -oA /tmp/dnp3_scan <ot-range>

   # PLC discovery with plcscan (Python 2 script — fails on Python 3; see tool doc)
   python plcscan.py <ot-target>
   ```

   See `../voip-ics/tools/plcscan.md` for PLC discovery options and `../information-gathering/tools/nmap.md` for NSE script usage.

   Risk gate: Never proceed to Phase 5 without classifying every discovered device. Safety-critical devices (PLCs controlling physical actuators, safety instrumented systems) require OT owner approval for ANY interaction, including read-only queries. If a device cannot be classified, treat it as safety-critical.

5. **Phase 5: ICS/OT Read-Only Assessment**

   Perform read-only assessment of ICS/OT devices. No write operations of any kind are permitted in this phase.

   - **Modbus register reads**: Use `modbus` (the Kali Python binary, not the Ruby gem) to read holding and input registers from Modbus devices. Record register values, data types, and device responses. Use `-s`/`--slave-id` to specify the Modbus unit ID identified in Phase 4.
   - **PLC identification and firmware checks**: Cross-reference firmware versions found in Phase 4 against known vulnerability databases. Check for end-of-life firmware or versions with published CVEs.
   - **Historian and HMI access testing**: If historian databases or HMI web interfaces are in scope, test whether they are accessible without authentication or with default credentials. Historians often expose process data that reveals operational details.
   - **IT/OT network segmentation verification**: Verify that proper segmentation exists between IT and OT networks. Check whether IT hosts can reach OT devices directly, whether firewall rules restrict traffic appropriately, and whether a DMZ separates the zones.

   ```bash
   # Read 10 holding registers starting at 100 from Modbus device (read-only)
   modbus -s 1 <ot-host>:502 h@100/10

   # Read input registers (i@) with verbose output
   modbus -s 1 -v <ot-host>:502 i@0/20

   # Read a block of holding registers, saving a snapshot for documentation
   modbus -s 1 <ot-host>:502 h@0/100 > /tmp/modbus_snapshot.txt

   # Check firmware versions against CVE databases
   searchsploit "siemens s7" -j > /tmp/s7_cves.json
   searchsploit "modbus" -j > /tmp/modbus_cves.json

   # Test IT-to-OT segmentation
   nmap -sn -T2 <ot-range>           # Can IT hosts reach OT?
   traceroute -T -p 502 <ot-host>    # What path does traffic take?
   ```

   See `../voip-ics/tools/modbus-cli.md` for register addressing formats and data types. See `../exploitation/tools/searchsploit.md` for vulnerability database queries.

   Strict rule: This phase is read-only. Only read registers (`h@`/`i@`). Never issue a write access spec (`w@`/`c@` with a value) or any command that changes device state. If a register read causes unexpected device behavior, stop immediately and notify the OT owner. Even read operations on safety-critical devices must be explicitly approved.

6. **Phase 6: IPMI/BMC and Network Infrastructure**

   Test out-of-band management interfaces, SNMP services, and other network infrastructure management protocols.

   - **IPMI enumeration**: Scan for IPMI services on UDP/623. Use `ipmitool` to check for unauthenticated access, retrieve system information, and test default credentials. IPMI cipher zero (unauthenticated access) is a critical finding.
   - **IPMI hash dumping**: If IPMI 2.0 is found, test for the RAKP authentication hash disclosure vulnerability (allows offline password cracking without authentication).
   - **SNMP community string testing**: Use `onesixtyone` to brute-force SNMP community strings against discovered SNMP services. Default strings `public` and `private` are commonly left unchanged.
   - **SNMP enumeration**: Use `snmpwalk` to enumerate sensitive OIDs including system information, network interfaces, routing tables, running processes, installed software, and ARP tables. SNMPv1/v2c community strings are sent in cleartext.
   - **Printer and MFP testing**: If network printers or multifunction printers are in scope, check for unauthenticated web interfaces, default credentials, PJL/PCL access, and stored print jobs.

   ```bash
   # IPMI service discovery
   nmap -sU -p 623 --script ipmi-version -T3 -oA /tmp/ipmi_scan <target-range>

   # IPMI system information (if accessible)
   ipmitool -I lanplus -H <bmc-host> -U ADMIN -P ADMIN chassis status
   ipmitool -I lanplus -H <bmc-host> -U ADMIN -P ADMIN user list 1

   # IPMI cipher zero check (unauthenticated access)
   nmap -sU -p 623 --script ipmi-cipher-zero <bmc-host>

   # IPMI password audit with NSE brute-force script (requires approval)
   nmap -sU -p 623 --script ipmi-brute <bmc-host>

   # SNMP community string brute force
   onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i /tmp/snmp_hosts.txt -o /tmp/snmp_communities.txt

   # SNMP enumeration with discovered community string
   snmpwalk -v2c -c <community> <host> 1.3.6.1.2.1.1          # System info
   snmpwalk -v2c -c <community> <host> 1.3.6.1.2.1.25.4.2.1.2 # Running processes
   snmpwalk -v2c -c <community> <host> 1.3.6.1.2.1.25.6.3.1.2 # Installed software

   # Printer web interface check
   nmap -sV -p 80,443,9100 --script http-title <printer-ip>
   ```

   See `../vulnerability/tools/onesixtyone.md` for community string brute-force options and `../vulnerability/tools/snmpwalk.md` for SNMP enumeration parameters. For credential testing workflows, see [Password Audit Playbook](password-audit.md).

   Risk gate: IPMI credential testing must respect lockout policies. If SNMPv3 with authentication is in use, do not attempt to bypass it without explicit approval. Printer testing should avoid modifying configurations or sending print jobs.

7. **Phase 7: Layer 2 protocol testing**

   Test Layer 2 protocol security when authorized and the network segment supports it.

   - Use `yersinia` for protocol-specific testing (see `../voip-ics/tools/yersinia.md`):

   ```bash
   # CDP/LLDP information gathering
   yersinia cdp -attack 0 -interface <iface>
   # DTP VLAN trunk negotiation test
   yersinia dtp -attack 1 -interface <iface>
   # STP root bridge claim test (high risk — confirm authorization)
   yersinia stp -attack 4 -interface <iface>
   ```

   - Risk gate: STP and DHCP attacks can disrupt production networks. Only execute with explicit authorization and in a controlled test window.
   - Document all Layer 2 findings with interface, protocol, and impact assessment.

8. **Phase 8: Evidence, Risk Assessment, and Escalation**

   Compile all findings, assess risk, and escalate safety-critical issues immediately.

   - **Protocol inventory**: Document every discovered specialized protocol instance by host, port, protocol, device type, firmware version, and criticality classification.
   - **Network segmentation assessment**: Summarize the segmentation posture between specialized protocol segments (voice VLAN, OT network, management network) and the general IT network. Note any missing segmentation boundaries.
   - **Finding compilation by criticality**: Organize findings into four severity tiers:
     - **Critical**: Unauthenticated access to safety-critical OT devices, IPMI cipher zero, unencrypted RTP on sensitive calls, writable Modbus registers accessible from IT network.
     - **High**: Default credentials on VoIP infrastructure, SNMPv1/v2c with write community strings, missing IT/OT segmentation, unpatched PLC firmware with known CVEs.
     - **Medium**: SIP without TLS, SNMP with default `public` community string (read-only), voice VLAN hopping possible, IPMI with weak passwords.
     - **Low**: Information disclosure via SNMP system descriptions, SIP server version banners, BACnet device names revealing internal naming conventions.
   - **Immediate escalation**: Safety-critical findings require immediate escalation to the OT owner and engagement lead. Do not wait for the final report. Examples: unauthenticated write access to PLCs, safety instrumented systems reachable from the IT network, active exploitation paths to devices controlling physical processes.
   - **Excluded tests documentation**: Record every active test that was not performed and why (e.g., "Modbus write tests excluded per OT owner request", "SIP brute force not authorized").

   ```bash
   # Compile all scan results
   ls -la /tmp/*_scan* /tmp/modbus_snapshot* /tmp/snmp_* /tmp/voip_*

   # Generate combined host/port/service inventory from nmap results
   grep "open" /tmp/*_scan*.gnmap | sort -u > /tmp/specialized_protocol_inventory.txt

   # Package evidence for reporting
   tar czf /tmp/specialized_protocols_evidence.tar.gz /tmp/*_scan* /tmp/modbus_snapshot* /tmp/snmp_* /tmp/voip_* 2>/dev/null
   ```

## Cross-References

- `internal-network.md` — network segmentation testing.
- `password-audit.md` — cracking captured SNMP community strings, SIP credentials, and IPMI hashes.
- `reporting-workflow.md` — report structure and delivery.

## Expected Artifacts

- Protocol inventory by host, port, protocol, device type, firmware version, and criticality level.
- VoIP assessment: SIP host list, extension enumeration results, credential test results (with approval evidence), VLAN hopping results, RTP encryption status.
- ICS/OT assessment: PLC/RTU device list with firmware versions, Modbus register snapshots (read-only), segmentation test results, CVE cross-reference output.
- IPMI/infrastructure assessment: BMC host list, cipher/authentication findings, SNMP community strings discovered, sensitive OID enumeration output.
- Network segmentation analysis between voice, OT, management, and IT segments.
- Excluded tests list with justification for each.
- Safety notes, stop conditions triggered, and emergency contact log.

## Stop When

- Approved discovery and read-only validation are complete for all in-scope protocols.
- Further work requires write operations to OT devices, live call interception, PLC firmware modification, or device-state changes.
- Any device instability, alarm, latency increase, or unexpected behavior is observed on OT or VoIP infrastructure.
- Credential attacks have reached the approved attempt limit or time budget.
