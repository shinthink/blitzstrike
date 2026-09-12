# External Attack Surface Playbook

Use for authorized domains, organizations, cloud keywords, or public IP ranges.

## Inputs

- Authorized root domains, company names, ASN/IP ranges, and cloud scope.
- Whether OSINT-only collection is required before active probing.
- API keys available for services such as Shodan or cloud discovery tools.

## Workflow

1. **Passive discovery**
   - Use `amass`, `subfinder`, `assetfinder` (see `../information-gathering/tools/assetfinder.md`), `theHarvester`, `shodan` (see `../information-gathering/tools/shodan.md`), and certificate/DNS sources (see `../information-gathering/tools/subfinder.md`, `../information-gathering/tools/theHarvester.md`, `../information-gathering/tools/amass.md`).
   - Keep passive and active findings separate.

   (See `../information-gathering/README.md` for reconnaissance tool selection.)
   - **Email security records**: check SPF (`dig TXT <domain>` and look for `v=spf1` records), DKIM, and DMARC (`dig TXT _dmarc.<domain>`) to identify email spoofing risk.
   - **Historical URL discovery**: query Wayback Machine and web archives for old endpoints, removed pages, and legacy API paths.
   - **Code repository exposure**: search for the organization's public repositories on GitHub/GitLab; check for `.git` directory exposure on discovered web servers.
   - **ASN-based IP range discovery**: look up the organization's ASN and enumerate associated IP ranges to broaden the target scope.

   ```bash
   amass enum -passive -d <domain> -oA amass_passive
   subfinder -d <domain> -o subfinder_domains.txt
   theHarvester -d <domain> -b google,linkedin,shodan -f harvester_results
   assetfinder --subs-only <domain> | tee assetfinder_domains.txt
   findomain -t <domain> -u findomain_domains.txt
   # Email security record checks (SPF is at the domain root, not _spf subdomain)
   dig TXT <domain>            # look for v=spf1 records
   dig TXT _dmarc.<domain>
   # Historical URL collection from web archives
   echo "<domain>" | gau -subs -o /tmp/gau_urls.txt
   # Certificate transparency graph
   certgraph -json <domain> > /tmp/certgraph.json
   ```

   Use `findomain` for fast passive subdomain discovery across multiple sources (see `../information-gathering/tools/findomain.md`). Use `getallurls` (`gau`) for historical URL collection from Wayback Machine and other web archives (see `../information-gathering/tools/getallurls.md`). Use `certgraph` for certificate transparency graph exploration (see `../information-gathering/tools/certgraph.md`).

   **Subdomain enumeration completeness:** Run at least three independent passive sources (e.g., amass, subfinder, certificate transparency logs via crt.sh). If any source produces unique results not found by others, add a fourth source. Do not rely on a single tool for subdomain discovery.

   **Credential discovery handling:** When credentials are found during passive discovery (exposed `.git` repositories, leaked config files, public code repositories, Shodan results with embedded credentials, historical URLs containing tokens), immediately test them against all discovered authentication endpoints before continuing to the next phase.

2. **DNS validation and expansion**
   - Validate candidates with `dnsx`, `massdns`, or `dig`.
   - Expand naming patterns with `dnsgen`, `altdns`, or `dnstwist` when appropriate.
   - Attempt zone transfers only against authorized domains.

   ```bash
   # Merge and deduplicate passive results, then validate
   cat *_domains.txt | sort -u > all_candidates.txt
   dnsx -l all_candidates.txt -a -cname -o dnsx_resolved.json -json
   # Expand and validate permutations
   dnsgen all_candidates.txt | massdns -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -t A -o S -w massdns_resolved.txt
   dig axfr @<ns-server> <domain>   # zone transfer attempt
   ```

3. **HTTP and port exposure**
   - Probe HTTP services with `httpx` (see `../information-gathering/tools/httpx.md`).
   - Use `naabu` (see `../information-gathering/tools/naabu.md`), `nmap` (see `../information-gathering/tools/nmap.md`), or `masscan` (see `../information-gathering/tools/masscan.md`) according to authorized depth and rate limits.
   - Capture titles, status codes, technologies, and TLS metadata.
   - **WAF/CDN identification**: use `wafw00f` results to determine the testing approach. If a CDN is detected, attempt to find the origin IP via historical DNS records, SSL certificate subjects, or direct IP scanning.

   **Full-range port coverage:** Do not rely solely on top-1000 ports. Run at least one full TCP port scan (`-p1-65535`) against all in-scope IPs. Compare results from `naabu` and `masscan` — if they disagree, re-scan the disputed ports with `nmap -sV` to confirm.

   ```bash
   httpx-toolkit -l resolved_domains.txt -title -tech-detect -status-code -json -o httpx_inventory.json
   naabu -l resolved_domains.txt -top-ports 1000 -json -o naabu_ports.json
   nmap -sS -sV -sC -iL resolved_ips.txt -oA external_scan
   masscan -p1-65535 --rate 1000 --include-file resolved_ips.txt -oJ masscan_results.json
   wafw00f -i resolved_domains.txt -o /tmp/waf_results.txt
   ```

   After port discovery, apply the two-phase confirmation, unknown service identification, and per-service test matrix from `internal-network.md` Phase 3.

4. **Subdomain takeover assessment**
   - Check for dangling CNAME records pointing to decommissioned cloud services (S3, Azure, Heroku, GitHub Pages, Fastly, Shopify).
   - Verify by checking if the CNAME target responds with an unclaimed service error page.
   - Cross-reference `dnsx` CNAME output against known takeover fingerprints.

   ```bash
   # Extract CNAME records and check for dangling targets
   dnsx -l all_candidates.txt -cname -resp-only -o cname_records.txt
   # Probe CNAME targets for unclaimed service indicators
   httpx-toolkit -l cname_records.txt -title -status-code -json -o takeover_candidates.json
   # Automated subdomain takeover detection
   subjack -w all_subdomains.txt -a -ssl -o /tmp/subjack_results.txt
   ```

   Use `subjack` for automated subdomain takeover detection across common cloud services (see `../web/tools/subjack.md`).

5. **Cloud exposure**
   - Use `cloud-enum` or `cloudbrute` only for cloud namespaces that are in scope.
   - Treat public buckets, exposed admin panels, and leaked endpoints as findings requiring validation.

   ```bash
   cloud_enum -k <company-name> -l /tmp/cloud_enum_results.txt
   cloudbrute -d <domain> -k <keyword> -m storage -o cloudbrute_results.txt
   ```

6. **Vulnerability triage**
   - Run low-impact `nuclei` templates first.
   - Run `nikto`, SSL/TLS checks, CMS scanners, and web playbook steps on confirmed live applications.

   (See `../vulnerability/README.md` for vulnerability scanner selection.)
   - **Triage decision logic**:
     - Findings with confirmed remote code execution, authentication bypass, or data exposure are immediately reportable.
     - Web applications with complex attack surfaces should be handed off to `web-application.md` for deeper testing.
     - Discovered API endpoints (REST, GraphQL, gRPC) should be handed off to `api-security.md`.
     - Informational findings (version disclosure, minor misconfigurations) are documented but deprioritized.
     - Subdomain takeover candidates confirmed in Phase 4 are high-priority findings.

   ```bash
   nuclei -l resolved_domains.txt -severity critical,high -o nuclei_triage.jsonl -jsonl
   testssl.sh --jsonfile /tmp/ssl.json --parallel <target>:443
   searchsploit <service-name> <version>   # match discovered services against Exploit-DB
   ```

7. **Evidence and deduplication**
   - Normalize hosts by domain, IP, port, scheme, and redirect target.
   - Deduplicate findings across domains and aliases before reporting.

## Cross-References

- `web-application.md` — for deeper testing of discovered web applications.
- `api-security.md` — for REST, GraphQL, gRPC, or WebSocket endpoints found during discovery.
- `internal-network.md` — when external reconnaissance reveals VPN, exposed internal services, or pivot opportunities.
- `reporting-workflow.md` — for structuring findings into a deliverable report.
- `cloud-native-assessment.md` — when cloud assets beyond simple storage buckets are discovered (e.g., exposed Kubernetes dashboards, cloud metadata endpoints).

## Expected Artifacts

- Root scope and discovery source list.
- Validated subdomains and DNS records.
- HTTP inventory with status, title, and technology.
- Public IP/port inventory.
- Confirmed exposure findings and false-positive notes.

## Stop When

- All discovered subdomains and IPs have been resolved, port-scanned, and service-fingerprinted with no new assets appearing on re-enumeration.
- Every exposed service has been triaged and handed off to the appropriate playbook (web, API, internal-network) or documented as informational.
- Remaining work requires authentication, exploitation, or a broader scope.
