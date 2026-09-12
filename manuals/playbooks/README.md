# Playbooks

Scenario playbooks describe how an agent should combine tools across categories. They are workflow guides, not parameter references.

Use them in this order:

1. Select the playbook that matches the authorized task.
2. Use the playbook to decide phases, stopping points, risk gates, and expected artifacts.
3. Read `../<category>/README.md` files — use Golden Path and Decision Tree to select suitable tools.
4. Read `../<category>/tools/<name>.md` only when running that tool.

## Decision Tree

Match the authorized target type to the correct playbook:

| Authorized Target | Playbook |
|-------------------|----------|
| IP range / CIDR / internal network | `internal-network.md` |
| Domain names / company name / public IPs | `external-attack-surface.md` |
| Web URL / web app | `web-application.md` |
| GraphQL / OpenAPI / gRPC / WebSocket API | `api-security.md` |
| Pure API endpoint (HTTP/HTTPS only, no other services) / user provides API docs, Swagger, or Postman collection | `api-security.md` |
| Active Directory domain / DC / Windows domain | `active-directory.md` |
| Hash file / credential list / service login | `password-audit.md` |
| Wi-Fi SSID / BSSID / wireless channel | `wireless-assessment.md` |
| Bluetooth / BLE target | `wireless-assessment.md` + `../wireless/README.md` |
| Cloud account / Kubernetes / container registry / Docker host | `cloud-native-assessment.md` |
| APK / IPA / mobile app runtime | `mobile-application.md` |
| RFID / NFC / smart card / physical credential / embedded device firmware | `rfid-nfc.md` |
| SIP / IAX / VoIP / ICS / OT / PLC / Modbus / IPMI / BMC | `voip-ics.md` |
| Existing shell / authorized initial access | `post-exploitation.md` |
| Disk image / memory dump / pcap / log files | `forensics-triage.md` |
| Source code repo / dependency manifests / CI artifacts | `source-code-audit.md` |
| Testing complete, need to produce a report | `reporting-workflow.md` |
| No match above / general pentest / unclear target type | `internal-network.md` (default) |

`internal-network.md` is the default playbook. When the target does not clearly match any specialized scenario above, start with `internal-network.md` — its host discovery, port scanning, and per-service testing workflow will reveal which specialized playbooks to switch to.

**Multi-playbook sequencing:** When a target matches multiple playbooks (e.g., an IP with web services matches both `internal-network.md` and `web-application.md`), start with `internal-network.md` for host and service discovery. Complete the per-service test matrix for all discovered services, then switch to specialized playbooks for deep testing. After completing a specialized playbook, return to the next unfinished phase of the originating playbook.

Cross-reference triggers during internal network testing:

- Discovered AD domain during internal network scan → switch to `active-directory.md`
- Discovered web app on enumerated host → switch to `web-application.md`
- Discovered API-heavy app or API schema → switch to `api-security.md`
- Target exposes only HTTP/HTTPS API (no other services) or user provides API documentation → switch to `api-security.md`
- Discovered Kubernetes, Docker API, registry, or cloud assets → switch to `cloud-native-assessment.md`
- Discovered VoIP or ICS/OT services → switch to `voip-ics.md`
- Gained initial access → switch to `post-exploitation.md`
- Discovered evidence of compromise (malware, unauthorized access, data exfiltration indicators) → switch to `forensics-triage.md`
- Captured hashes during AD enumeration → switch to `password-audit.md`

## Available Playbooks

| Scenario | File | Coverage |
|----------|------|----------|
| Internal network or full pentest | `internal-network.md` | Host discovery, port scanning, service enumeration, vulnerability validation, credential testing, and pivot to specialized playbooks |
| Internal network protocols | `internal-network-protocols.md` | SMB, MSRPC, SNMP, SMTP, DNS, database, and RDP protocol-specific enumeration and testing |
| External attack surface | `external-attack-surface.md` | OSINT, subdomain enumeration, port/service discovery, web fingerprinting, and handoff to web/API playbooks |
| Web application | `web-application.md` | Crawling, DAST scanning, authentication testing, injection, CMS-specific checks, and manual validation |
| API security | `api-security.md` | Schema recovery, endpoint discovery, auth/authorization testing (BOLA, JWT), fuzzing, rate limiting, and business logic |
| Active Directory | `active-directory.md` | AD enumeration, Kerberoasting, AS-REP roasting, relay attacks, ACL abuse, AD CS, credential extraction, and domain escalation |
| Password audit | `password-audit.md` | Hash identification, offline cracking (hashcat/john), password spraying, default credentials, and credential reuse |
| Wireless assessment | `wireless-assessment.md` | Adapter setup, WiFi reconnaissance, handshake capture, WPS attacks, evil twin, Bluetooth/BLE enumeration, and post-authentication |
| Cloud-native assessment | `cloud-native-assessment.md` | Multi-cloud posture, provider-specific audits (AWS/Azure/GCP), Kubernetes security, container/registry scanning, and serverless review |
| Mobile application assessment | `mobile-application.md` | Static analysis, data storage review, network security, runtime instrumentation, and binary protection |
| RFID/NFC assessment | `rfid-nfc.md` | Card identification, RFID/NFC assessment, smart-card testing, embedded device checks, and firmware analysis |
| VoIP/ICS protocols | `voip-ics.md` | VoIP/SIP enumeration, ICS/OT discovery, IPMI/BMC checks, SNMP testing, and protocol-specific read-only validation |
| Post-exploitation | `post-exploitation.md` | Privilege escalation, credential harvesting, lateral movement, persistence, tunneling, and C2/adversary emulation |
| Forensics triage | `forensics-triage.md` | Evidence handling, memory/disk/network analysis, timeline construction, log analysis, and artifact extraction |
| Source code & dependency audit | `source-code-audit.md` | SAST, secret scanning, dependency/SCA analysis, IaC scanning, and CI/CD pipeline review |
| Reporting workflow | `reporting-workflow.md` | Finding organization, severity scoring (CVSS), evidence packaging, report generation, and delivery |

## Cross-Reference Map

Playbooks frequently hand off to each other as new signals emerge during testing:

| Source Playbook | Target Playbook | Trigger |
|----------------|-----------------|---------|
| `internal-network` | `internal-network-protocols` | Protocol-specific testing needed |
| `internal-network` | `active-directory` | AD domain discovered |
| `internal-network` | `web-application` | HTTP service found |
| `internal-network` | `api-security` | API endpoints found |
| `internal-network` | `cloud-native-assessment` | Kubernetes/Docker/cloud metadata |
| `internal-network` | `voip-ics` | VoIP/ICS/OT services |
| `internal-network` | `password-audit` | hashes captured |
| `internal-network` | `post-exploitation` | initial access gained |
| `external-attack-surface` | `web-application` | web app discovered |
| `external-attack-surface` | `api-security` | API endpoint discovered |
| `external-attack-surface` | `reporting-workflow` | findings ready |
| `active-directory` | `password-audit` | hashes for cracking |
| `active-directory` | `post-exploitation` | domain compromised |
| `cloud-native-assessment` | `internal-network` | VPC network testing |
| `cloud-native-assessment` | `post-exploitation` | container escape |
| `cloud-native-assessment` | `source-code-audit` | CI/CD pipeline review |
| `cloud-native-assessment` | `reporting-workflow` | findings ready |
| `forensics-triage` | `password-audit` | encrypted evidence |
| `forensics-triage` | `reporting-workflow` | documentation |
| `rfid-nfc` | `wireless-assessment` | Bluetooth proximity |
| `rfid-nfc` | `reporting-workflow` | evidence packaging |
| `api-security` | `web-application` | general web testing |
| All playbooks | `reporting-workflow` | final deliverable |

## Category References

After selecting a playbook, read the category README to choose suitable tools:

| Scope | Reference |
|-------|-----------|
| Information gathering & OSINT | `../information-gathering/README.md` |
| Vulnerability analysis | `../vulnerability/README.md` |
| Sniffing & spoofing | `../sniffing-spoofing/README.md` |
| Web application and API testing | `../web/README.md` |
| Exploitation & pivoting | `../exploitation/README.md` |
| Password attacks & cracking | `../password/README.md` |
| Wireless & Bluetooth | `../wireless/README.md` |
| Cloud-native security | `../cloud-native/README.md` |
| Reverse engineering | `../reverse-engineering/README.md` |
| RFID/NFC | `../rfid-nfc/README.md` |
| VoIP/ICS protocols | `../voip-ics/README.md` |
| Forensics & triage | `../forensics/README.md` |
| Post-exploitation tools | `../post-exploitation/README.md` |
| Reporting | `../reporting/README.md` |
