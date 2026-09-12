# Forensics Triage Playbook

Use for authorized analysis of disk images, memory dumps, packet captures, logs, files, or suspected hidden data.

## Inputs

- Evidence files, hashes if provided, case objective, and allowed output location.
- Whether destructive writes are prohibited. Default to read-only handling.
- Target operating system or acquisition source if known.
- Available evidence types: memory dump, disk image, PCAP, Windows event logs, individual files.

## Workflow

1. **Evidence acquisition and handling**
   - Follow order of volatility: acquire memory first, then disk images, then network captures, then logs and files.
   - Verify write-blocking before imaging. Confirm hardware or software write-blocker is active.
   - Start chain of custody documentation: who acquired what, when, from which system, with what tool, and hash verification.
   - Always work on forensic copies, never originals. Create working copies from verified images.

   (See `../forensics/README.md` for forensic tool selection.)

   ```bash
   # Create forensic disk image with hash verification
   dc3dd if=/dev/sdb hof=/tmp/evidence_image.dd hash=sha256 log=/tmp/acquisition.log
   # Alternative: dcfldd with inline hashing
   dcfldd if=/dev/sdb of=/tmp/evidence.dd hash=sha256 hashlog=/tmp/hashes.txt
   # For damaged media: ddrescue with error mapping
   ddrescue -d /dev/sdb /tmp/evidence.dd /tmp/ddrescue.map
   # Verify image integrity
   sha256sum /tmp/evidence_image.dd >> /tmp/evidence_hashes.txt
   ```

   Use `dc3dd` for forensic imaging with inline hashing (see `../forensics/tools/dc3dd.md`). Use `dcfldd` as an enhanced alternative to `dc3dd` with inline hashing and split output (see `../forensics/tools/dcfldd.md`). Use `ddrescue` for imaging damaged or failing media with automatic retry and error mapping (see `../forensics/tools/ddrescue.md`).

   Decision branching based on available evidence:
   - Memory dump available: proceed to Phase 3 (memory analysis).
   - Disk image available: proceed to Phase 4 (timeline construction), then Phase 5 (disk and file recovery).
   - PCAP available: proceed to Phase 6 (traffic analysis).
   - Windows event logs available: proceed to Phase 7 (registry and application artifacts) and Phase 8 (logs and metadata).
   - Combine all findings in Phase 9 (anti-forensics detection) before reporting.

2. **Identify file types**
   - Use `file`, `binwalk` when available (see `../reverse-engineering/tools/binwalk.md`), `exiftool` (see `../forensics/tools/exiftool.md`), and archive tools as appropriate.
   - For disk images, identify partitions and filesystems before extraction.

   ```bash
   exiftool <file> > /tmp/exiftool_metadata.txt
   foremost -t all -i <disk-image> -o /tmp/foremost_recovery/
   bulk_extractor -o /tmp/bulk_output/ <disk-image>
   ```

   Use `foremost` for file carving from disk images (see `../forensics/tools/foremost.md`). Use `bulk_extractor` for bulk data extraction including emails, URLs, and credit card numbers (see `../forensics/tools/bulk-extractor.md`).

3. **Memory analysis**
   - Use `volatility` with the correct profile/symbols (see `../forensics/tools/volatility.md`).
   - Extract process, network, credential, malware, and timeline indicators according to case objective.

   ```bash
   vol -f <memory-dump> windows.info                     # OS/version info
   vol -f <memory-dump> windows.pslist                   # process list
   vol -f <memory-dump> windows.netscan                  # network connections
   vol -f <memory-dump> windows.registry.hashdump        # credential hashes
   ```

4. **Timeline construction**
    - Correlate filesystem MAC times (Modified, Accessed, Changed) with event logs and memory artifacts to build a unified timeline.
    - Use `plaso`/`log2timeline` to ingest multiple evidence sources into a single normalized timeline:

    ```bash
    plaso-log2timeline /tmp/timeline.plaso /path/to/evidence
    plaso-psort -o l2tcsv -w /tmp/timeline.csv /tmp/timeline.plaso
    ```

    - Focus on: file creation/modification around incident window, process execution times from memory, network connections with timestamps, and log entries.

    **Cross-source correlation:** Do not analyze each evidence type in isolation. For every suspicious artifact (process, connection, file), search for corroborating evidence in at least one other source (memory ↔ disk ↔ traffic ↔ logs). Uncorroborated findings should be flagged, not silently dropped.

    ```bash
    # Extract filesystem timeline from disk image
    fls -r -m / <disk-image> > /tmp/bodyfile.txt
    mactime -b /tmp/bodyfile.txt -d > /tmp/filesystem_timeline.csv
    # Merge with Volatility timeline output
    vol -f <memory-dump> timeliner.Timeliner > /tmp/memory_timeline.txt
    ```

    - Cross-reference timestamps across sources to identify: initial compromise time, lateral movement, data staging, and exfiltration windows.
    - Flag timestamp inconsistencies for anti-forensics review (Phase 9).

5. **Disk and file recovery**
   - Use `dc3dd`, `foremost`, `bulk-extractor`, and filesystem tools.
   - Preserve recovered output paths and hashes.

   ```bash
   dc3dd if=/dev/sdb hof=/tmp/disk_image.dd hash=sha256 log=/tmp/dc3dd.log
   foremost -t jpg,png,pdf,zip -i /tmp/disk_image.dd -o /tmp/recovered/
   # Scalpel file carving with configurable signatures
   scalpel -c /etc/scalpel/scalpel.conf -o /tmp/scalpel_out/ /tmp/disk_image.dd
   ```

   Use `scalpel` alongside `foremost` for file carving with more configurable signature definitions (see `../forensics/tools/scalpel.md`).

   Verify recovered file integrity with `hashdeep` and identify similar files with `ssdeep` fuzzy hashing:

   ```bash
   hashdeep -r -l /tmp/recovered/ > /tmp/hashset.txt
   ssdeep -r /tmp/extracted/ > /tmp/fuzzy.txt && ssdeep -d /tmp/fuzzy.txt
   ```

   Use `hashdeep` for recursive hash verification of recovered evidence (see `../forensics/tools/hashdeep.md`). Use `ssdeep` for fuzzy hash matching to identify similar or modified files across evidence sets (see `../forensics/tools/ssdeep.md`).

   5.1. **Malware triage**
   - Scan extracted files and suspicious artifacts with YARA rules.
   - Use community rule sets or write custom rules for engagement-specific indicators.

   ```bash
   yara -r /path/to/rules/ /tmp/extracted_files/
   yara -r /usr/share/yara-rules/ /path/to/suspicious_file
   ```

   - Cross-reference hits with hash databases and VirusTotal (if authorized).
   - Document malware artifacts with file path, hash, YARA rule match, and timestamps.

6. **Traffic analysis**
   - Use `tcpdump` and `tshark` for conversations, protocols, credentials, files, DNS, HTTP, TLS, and timelines (see `../forensics/tools/tshark.md` and `../forensics/tools/tcpdump.md`).

   ```bash
   tshark -r capture.pcap -q -z conv,tcp                  # conversation summary
   tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
   tcpdump -r capture.pcap -n 'port 53'                   # DNS queries
   # Reassemble TCP streams into individual files
   tcpflow -r capture.pcap -o /tmp/tcpflow_out/
   ```

   Use `tcpflow` to reassemble and extract TCP stream content from packet captures for deeper content analysis (see `../forensics/tools/tcpflow.md`).

7. **Registry and application artifact analysis**
    - Windows registry hive examination for persistence mechanisms, user activity, and device history:
      - SAM: local user accounts and password policy.
      - SYSTEM: services, drivers, computer name, timezone, network interfaces.
      - SOFTWARE: installed programs, autorun entries, OS configuration.
      - NTUSER.DAT: per-user MRU lists, typed URLs, recent documents, UserAssist, shellbags.
      - USB history: USBSTOR entries in SYSTEM hive, setupapi logs, and mountpoints in NTUSER.DAT.

    ```bash
    # Parse registry hives with regripper (if available)
    regripper -r /tmp/mounted/Windows/System32/config/SAM -f sam > /tmp/reg_sam.txt
    regripper -r /tmp/mounted/Windows/System32/config/SYSTEM -f system > /tmp/reg_system.txt
    regripper -r /tmp/mounted/Windows/System32/config/SOFTWARE -f software > /tmp/reg_software.txt
    regripper -r /tmp/mounted/Users/<username>/NTUSER.DAT -f ntuser > /tmp/reg_ntuser.txt
    ```

    - Browser artifact analysis: history databases, download records, cached pages, and saved credentials from Chrome, Firefox, and Edge profile directories.
    - Windows event log analysis with `chainsaw` for targeted detection:

    ```bash
    # Hunt for known attack patterns using Sigma rules
    chainsaw hunt <evtx-directory> -s /usr/share/sigma/rules/windows/ --mapping chainsaw/mappings/sigma-event-logs-all.yml
    # Search for specific event IDs
    chainsaw search -t 'Event.System.EventID: =4624' <evtx-directory>    # logon events
    chainsaw search -t 'Event.System.EventID: =4688' <evtx-directory>    # process creation
    chainsaw search -t 'Event.System.EventID: =7045' <evtx-directory>    # service installation
    ```

8. **Logs and metadata**
   - Use `chainsaw` for Windows event logs (see `../forensics/tools/chainsaw.md`), `exiftool` for metadata (see `../forensics/tools/exiftool.md`), and `stegseek` for steganography passphrase cracking when relevant (see `../forensics/tools/stegseek.md`).

   ```bash
   chainsaw hunt <evtx-directory> -s /usr/share/sigma/rules/windows/ --mapping chainsaw/mappings/sigma-event-logs-all.yml
   stegseek <suspicious.jpg> /usr/share/wordlists/rockyou.txt   # fast passphrase crack
   ```

   **Linux evidence sources:** For Linux systems, also check: `/var/log/auth.log`, `/var/log/syslog`, `.bash_history` for all users, `/etc/crontab` and `/var/spool/cron/`, SSH authorized keys and known hosts, systemd journal (`journalctl`), and `/tmp/` for dropped tools.

9. **Anti-forensics detection**
   - Detect timestomping: look for MAC time anomalies where $STANDARD_INFORMATION timestamps differ from $FILE_NAME timestamps (NTFS), or where creation time is after modification time.
   - Detect log clearing: gaps in sequential event log records, Event ID 1102 (audit log cleared), or missing expected log files.
   - Detect data wiping: look for artifacts of secure-deletion tools (e.g., `sdelete`, `cipher /w`), large clusters of zeroed sectors, or filesystem journal anomalies.
   - Detect encrypted containers: identify TrueCrypt/VeraCrypt containers, BitLocker volumes, or other encrypted partitions. If encrypted evidence is found, refer to the [password audit playbook](password-audit.md) for decryption approaches.

   ```bash
   # Check for timestomping via MFT analysis (NTFS)
   vol -f <memory-dump> windows.mftscan > /tmp/mft_analysis.txt
   # Look for log clearing events
   chainsaw search -t 'Event.System.EventID: =1102' <evtx-directory>
   # Identify encrypted volumes
   file /tmp/recovered/* | grep -i 'encrypted\|truecrypt\|bitlocker'
   # Rootkit detection on mounted evidence
   chkrootkit -r /tmp/mounted/
   rkhunter --check --skip-keypress --report-warnings-only
   ```

   Use `chkrootkit` and `rkhunter` to scan mounted evidence for rootkits, backdoors, and suspicious system modifications (see `../forensics/tools/chkrootkit.md` and `../forensics/tools/rkhunter.md`).

   - Cross-reference anti-forensics indicators with the timeline (Phase 4) to determine if evidence destruction occurred after the incident.

## Cross-References

- `password-audit.md` — encrypted evidence cracking.
- `post-exploitation.md` — credential hashes extracted from memory analysis feed into post-exploitation workflows.
- `reporting-workflow.md` — findings documentation and report structure.

## Expected Artifacts

- Evidence inventory, chain of custody log, and hashes.
- Unified timeline correlating filesystem, memory, and log sources.
- Extracted indicators, files, timelines, and protocol summaries.
- Registry and application artifact findings.
- Anti-forensics indicators and evidence integrity assessment.
- Tool logs and recovered artifact locations.
- Findings tied to source evidence.

## Stop When

- The case objective has been answered with evidence-backed conclusions.
- All available evidence types (memory, disk, traffic, logs) have been analyzed and cross-referenced in the unified timeline.
- Anti-forensics detection is complete and all identified evidence gaps are documented.
- Additional analysis would require destructive modification, password cracking, or out-of-scope data review.
