# Internal Network Playbook

Use for authorized internal ranges, lab networks, or full pentest tasks where the starting point is an IP, CIDR, or known host.

## Inputs

- Authorized IPs/CIDRs and excluded hosts.
- Allowed scan windows, rate limits, and intrusive-test limits.
- Kali execution mode and network reachability from Kali.

## Workflow

1. **Connectivity and routing**
   - Verify Kali can reach the target range with `ip route`, `ping`, `arp`, or protocol-specific checks.
   - If Docker cannot reach a host that the host OS can reach, follow `../environment/docker-mode-networking.md`.

   ```bash
   ip route            # confirm default gateway and subnet routes
   ping -c 3 <target>  # basic reachability
   arp -a              # check ARP table for local hosts
   ```

2. **Host discovery**
   - Use low-noise discovery first: `nmap -sn`, `fping`, `arp-scan` for local LAN, or `masscan` only when authorized.
   - Include IPv6 host discovery. Many internal networks have IPv6 enabled but unmonitored, making it a valuable attack surface.
   - Save a live-host list for later phases.

   Use `nmap -sn` for ping sweep or `arp-scan` for local LAN (see `../information-gathering/tools/nmap.md` for host discovery flags; see `../information-gathering/README.md` for tool selection).

   ```bash
   arp-scan --localnet                     # ARP-based, LAN only, very fast
   fping -a -g <CIDR> 2>/dev/null > live_hosts.txt
   # IPv6 host discovery
   nmap -6 -sn <prefix>                    # IPv6 ping sweep on known prefix
   ping6 ff02::1%<interface>               # link-local all-nodes multicast
   # Derive target IPv6 from MAC (same LAN): ping6 multicast, then check neighbor table
   ip -6 neigh | grep <target-mac>         # find target's link-local address after multicast ping
   ```

   **Zero-findings fallback:** If no live hosts are found, verify network connectivity (Phase 1), broaden discovery methods (add ARP scan, TCP SYN to common ports, IPv6 multicast), and check for host-based firewalls blocking ICMP. Do not proceed to Phase 3 with an empty host list.

3. **Port and service mapping**
   - Run top-port TCP discovery, then full TCP on live/key hosts.
   - Follow with service/version detection and safe NSE scripts using `nmap`.
   - UDP scanning by depth:
     - Standard: `nmap -sU --top-ports 20` (covers SNMP/161, DNS/53, NTP/123, TFTP/69, IPMI/623, NetBIOS/137).
     - Deep: `nmap -sU --top-ports 100` or targeted based on discovered TCP services.
     - Always scan UDP/161 and UDP/623 on infrastructure devices (routers, switches, BMCs).

   Start with top-port TCP + version detection on live hosts (see `../information-gathering/tools/nmap.md` for port range, timing, and output format variants; see `../information-gathering/README.md` for tool selection).

   ```bash
   nmap -sV -sC --top-ports 1000 -oA quick_tcp -iL live_hosts.txt
   nmap -sV -p- -oA full_tcp <key-host>
   ```

   **Two-phase confirmation (mandatory):** High-speed scans (`--min-rate 2000`) can drop packets in Docker Desktop or congested networks, causing ports to be silently missed. After the high-speed pass, confirm all open ports with a low-speed retry scan before proceeding:

   ```bash
   # Phase 1: fast full-port discovery
   nmap -sT -Pn -p- --min-rate 2000 -oA /tmp/scan_fast <target>
   # Extract discovered ports
   PORTS=$(grep '/open/' /tmp/scan_fast.gnmap | grep -oP '\d+/open' | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
   # Phase 2: low-speed confirmation + version + scripts
   nmap -sT -Pn -p "$PORTS" --min-rate 200 --max-retries 5 -sV -sC -oA /tmp/scan_confirm <target>
   ```

   **Zero-findings fallback:** If a confirmed-live host shows zero open ports, retry with `-sT -Pn -p-` (full TCP connect scan, skip host discovery). Check for transparent firewalls or IDS dropping probes. If still zero ports, document the host as fully filtered and proceed to the next host.

   **Unknown service identification (mandatory):** When nmap cannot identify a service (labels it `unknown`, `tcpwrapped`, or adds a `?` suffix), probe it before moving on:

   ```bash
   # Step 1: TLS certificate metadata
   openssl s_client -connect <ip>:<port> </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
   # Step 2: ALPN negotiation (try known protocols)
   openssl s_client -alpn h2 -connect <ip>:<port> </dev/null 2>/dev/null | grep -E 'ALPN|Protocol'
   openssl s_client -alpn http/1.1 -connect <ip>:<port> </dev/null 2>/dev/null | grep -E 'ALPN|Protocol'
   # Step 3: Banner capture
   nc -w3 <ip> <port> 2>/dev/null | head -c 512 | xxd | head
   curl -sk https://<ip>:<port>/ -o /dev/null -w '%{http_code}\n'
   ```

   Only mark a service as "unidentified" after completing all steps above.

   **Script result verification:** When nmap NSE scripts report ambiguous or error-containing results (partial success, timeout warnings, PASV mismatch, unexpected error codes), verify with manual protocol interaction or a second tool. Do not mark a service test as complete based on a script that did not fully succeed.

   **Per-service test matrix:** After identifying each service, complete all applicable items before moving to the next service:

   | Test | Must complete for |
   |------|-------------------|
   | Precise version (minor level) | All services |
   | CVE evaluation with version range check | All services |
   | Anonymous / unauthenticated access | All services |
   | Protocol-level deep probe (RPC endpoints, ALPN, named pipes, handshake) | All services |
   | Credential attack: fasttrack wordlist + target-specific terms | All auth services |
   | Configuration security (signing, cipher strength, access control) | All services |
   | Attack chain: can this weakness combine with another finding? | All findings |

   **Reduced matrix for duplicate/auxiliary ports:** For dynamic RPC endpoints (49152-65535), secondary listeners of an already-tested service (e.g., WinRM on 47001 when 5985 is tested), or the same service on multiple ports, confirm the service identity and version only — skip the full matrix.

   Record both positive findings and explicitly tested-but-no-finding negative results for each service.

   **Locally-bound services:** When a service rejects connections based on source IP (e.g., MySQL `Host not allowed`, PostgreSQL pg_hba deny), mark it as "locally-bound — retest after shell access." Maintain a deferred-testing list for these services. After gaining initial access (Phase 8), return to this list and test each service from the compromised host.

   **AD domain discovery:** When AD domain information is discovered during service scanning (domain names, computer names, user accounts via RID cycling), record it for the `active-directory.md` handoff but continue completing the per-service test matrix before switching.

   **CVE evaluation procedure:** For each service with an identified version: (1) `searchsploit <service> <version>` for offline Exploit-DB lookup, (2) `getsploit <service> <version>` for online multi-database search, (3) `nuclei -tags cve` against the service for template-based CVE detection, (4) manual check of NVD and vendor security advisories for recent or unindexed CVEs, (5) for application frameworks with plugin ecosystems (WordPress, Joomla, Drupal), use CMS-specific scanners (`wpscan`, `joomscan`, `droopescan`) — searchsploit and nuclei may not cover third-party plugin vulnerabilities.

4. **Network infrastructure and segmentation**
   - Enumerate network devices (routers, switches, firewalls) via SNMP and management interfaces.
   - Test VLAN segmentation — determine whether you can reach VLANs outside your authorized segment.
   - Test network device default credentials on discovered management interfaces.
   - Internal DNS enumeration: attempt zone transfers and reverse DNS sweeps.

   ```bash
   # DNS zone transfer attempt
   dig axfr @<dns-server> <domain>
   # Reverse DNS sweep on a /24
   nmap -sL <CIDR> | grep '(' | awk '{print $5}'
   # SNMP enumeration on network devices
   snmpwalk -v2c -c public <router-ip> 1.3.6.1.2.1.4.20  # IP address table
   snmpwalk -v2c -c public <switch-ip> 1.3.6.1.2.1.17    # bridge/VLAN table
   ```

5. **Protocol enumeration**

   Route discovered services to the appropriate playbook or protocol reference:

   - HTTP/HTTPS: distinguish the service type before switching playbooks:
     - Custom web application or CMS (unknown app, WordPress, Joomla, etc.): switch to `web-application.md`.
     - Known product with web UI (Jenkins, Grafana, Cockpit, phpMyAdmin, Kibana, etc.): test version + known CVEs + default/discovered credentials + product-specific misconfigurations only. Do not run the full `web-application.md` workflow.
     - Static or default page (Apache/Nginx welcome, directory listing): directory enumeration + technology fingerprint only.
   - API-heavy HTTP, OpenAPI, GraphQL, gRPC, or WebSocket: switch to `api-security.md`. An HTTP service is API-heavy when it returns `application/json` content-type, exposes `/api-docs`, `/swagger`, `/openapi.json`, or `/graphql` endpoints, or when `whatweb`/`httpx` identifies API frameworks (Express, FastAPI, Spring Boot, Django REST).
   - Kubernetes, Docker API, container registries, cloud metadata: switch to `cloud-native-assessment.md`.
   - SIP, IAX, VoIP, ICS/OT, PLC, Modbus: switch to `voip-ics.md`.
   - All other protocols (SMB, MSRPC, SNMP, Kerberos, LDAP, RDP, WinRM, SSH, FTP, databases, mail, NFS, IPMI, Redis/NoSQL): follow `internal-network-protocols.md`.

   **Playbook handoff:** When a discovered service triggers a switch to another playbook, complete that playbook's workflow, then return here to continue with the next service.

   **Credential discovery handling:** When credentials are found during any phase (backup files on FTP/SMB, config pages, nmap script output, SNMP community strings), immediately add them to the working credential list. Test each credential against all discovered authentication services (SSH, FTP, databases, web logins, APIs) before proceeding to the next phase. Do not defer credential testing to Phase 7 — discovered credentials may unlock deeper enumeration in the current phase.

   **Coverage requirement:** For every discovered service, complete the full per-service test matrix from Phase 3 before marking the service as tested. Do not skip protocols that appear uninteresting — test them systematically.

6. **Vulnerability assessment**
   - Scan non-HTTP services for known vulnerabilities: `nuclei` network templates, SSL/TLS configuration checks (`testssl.sh`/`sslscan`), and protocol-specific vulnerability NSE scripts.
   - Use GVM/OpenVAS only for Deep scans when initialized and authorized.
   - Note LLMNR/NBT-NS/mDNS poisoning exposure: if these protocols are active on the network, `responder` can capture credentials passively. Captured hashes should be forwarded to `password-audit.md` for offline cracking.

   (See `../vulnerability/README.md` for vulnerability scanner selection.)

   ```bash
   # Quick CVE scan on discovered web services
   httpx-toolkit -l live_hosts.txt -p 80,443,8080,8443 -o web_urls.txt
   nuclei -l web_urls.txt -severity critical,high -o nuclei_critical.jsonl -jsonl
   # SSL/TLS on key hosts
   testssl.sh --jsonfile /tmp/ssl_<ip>.json <ip>:443
   # Passive credential capture (authorized networks only)
   responder -I <interface> -A   # analyze mode — listen only, no poisoning
   ```

7. **Credential checks**
   - This phase covers proactive credential testing — default credentials, password spraying, and brute-force. Credentials discovered organically during earlier phases should already have been tested per the credential discovery handling directive.
   - Test default credentials and known credentials only within the authorized lockout policy.
   - Use `netexec` for multi-protocol default credential testing across discovered services.
   - Switch to `password-audit.md` for hash cracking, password spraying, or brute force.

   (See `../password/README.md` for credential tool selection.)

   ```bash
   # Multi-protocol credential testing with nxc
   nxc smb <CIDR> -u 'administrator' -p 'admin'        # SMB default creds
   nxc winrm <CIDR> -u <user> -p <password>            # WinRM access
   nxc ssh <CIDR> -u root -p root                      # SSH default creds
   nxc mssql <CIDR> -u sa -p 'sa'                      # MSSQL default creds
   nxc ldap <CIDR> -u <user> -p <password>             # LDAP bind testing
   nxc smb <CIDR> -u 'administrator' -p 'admin' --local-auth   # local account (non-domain)
   ```

8. **Exploitation and post-exploitation**
   - Exploit only confirmed vulnerabilities and only after explicit approval. See `../exploitation/README.md` for the exploitation decision tree (known CVE, web vulnerability, valid credentials, tunnel/pivot path selection).
   - If initial access is gained, switch to `post-exploitation.md` and restart reconnaissance on newly discovered in-scope networks. After post-exploitation completes on a host, return here to test deferred services from the compromised host and exploit remaining targets using newly discovered credentials.
   - When multiple exploitation paths exist, prioritize by: reliability (proven exploit > PoC), stealth (credential-based > RCE), and reversibility (login > code execution).

   ```bash
   # After gaining shell: stabilize, enumerate, escalate
   python3 -c 'import pty; pty.spawn("/bin/bash")'    # TTY upgrade
   ./linpeas.sh > /tmp/linpeas_<target>.txt           # Linux privesc enum
   ./winpeas.exe > C:\Temp\winpeas_<target>.txt       # Windows privesc enum
   # Verify exploitation success: confirm access level and network position
   id && hostname && ip addr show
   ```

## Cross-References

- `internal-network-protocols.md` — protocol-specific testing procedures for Phase 5 (integral — always read for non-HTTP protocol testing).
- `active-directory.md` — domain enumeration, Kerberoasting, AS-REP roasting, and AD escalation paths.
- `web-application.md` — web service testing for discovered HTTP/HTTPS endpoints.
- `api-security.md` — API testing for discovered REST, GraphQL, gRPC, or WebSocket services.
- `cloud-native-assessment.md` — when Kubernetes API, Docker daemon, or cloud service endpoints are discovered.
- `voip-ics.md` — when VoIP/SIP, ICS/OT/Modbus, or IPMI/BMC services are discovered.
- `password-audit.md` — hash cracking for captured NTLM, NTLMv2, and Kerberos hashes.
- `post-exploitation.md` — post-exploitation activities after gaining initial access.
- `wireless-assessment.md` — when wireless access points or Bluetooth devices are discovered on the internal network.
- `reporting-workflow.md` — evidence packaging and report generation.

## Expected Artifacts

- Live hosts list (IPv4 and IPv6).
- Nmap `-oA` output and parsed open-port summary.
- Service inventory by host.
- Network infrastructure map (routers, switches, VLANs, DNS zones).
- Vulnerability scan output with severity and evidence.
- Credential test results with lockout-safe notes.
- Captured hashes and credential artifacts (if applicable).

## Stop When

- All in-scope live hosts have service inventories.
- Standard vulnerability and protocol checks are complete.
- Network segmentation and infrastructure enumeration are documented.
- Further progress requires intrusive exploitation or out-of-scope pivots.
