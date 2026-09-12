# Third-Party Notices

Blitz Strike vendors data, playbooks, and tool references from the following
open-source projects. Each retains its original license and copyright. This file
satisfies the attribution requirements of those licenses.

---

## adversary-playbook

- **Source:** https://github.com/isoloman275-wq/adversary-playbook
- **License:** MIT
- **Copyright (c)** 2026 NZ1Labs / Ihaka Soloman
- **Used for:** 14 offensive security playbooks (`skills/ap-*.md`).

## hack.proof

- **Source:** https://github.com/ca-who-codes/hack.proof
- **License:** MIT
- **Copyright (c)** 2026 ca-who-codes
- **Used for:** 18 security-audit playbooks (`skills/hp-*.md`).

## kali-pentest

- **Source:** https://github.com/x-glacier/kali-pentest
- **License:** Apache-2.0
- **Used for:** 270 deep tool manuals (`manuals/<category>/<tool>.md`) + 17
  engagement playbooks (`manuals/playbooks/`).

## airecon

- **Source:** https://github.com/pikpikcu/airecon
- **License:** MIT
- **Copyright (c)** 2026 pikpikcu
- **Used for:** 21 JSON intelligence data files (`intelligence/*.json`) —
  WAF signatures, tech/CVE/port correlations, fuzzer data, vuln ontology,
  attack chains, WAF bypass strategies, A/B signals, and patterns.

## PayloadsAllTheThings

- **Source:** https://github.com/swisskyrepo/PayloadsAllTheThings
- **License:** MIT
- **Used for:** 66 exploit-payload categories (`payloads/*/`).

## nuclei-templates

- **Source:** https://github.com/projectdiscovery/nuclei-templates
- **License:** MIT
- **Used for:** ~11.9k YAML detection templates (`templates/`).

## OWASP Web Security Testing Guide (WSTG)

- **Source:** https://github.com/OWASP/wstg
- **License:** CC BY-SA 4.0
- **Used for:** the WSTG category/test taxonomy in `intelligence/wstg_map.json`
  (category identifiers WSTG-INFO/CONF/IDNT/ATHN/ATHZ/SESS/INPV/ERRH/CRYP/
  BUSL/CLNT/APIT and their test names).

## OWASP API Security Top 10

- **Source:** https://github.com/OWASP/API-Security
- **License:** CC BY-SA 4.0
- **Used for:** the 2023 risk taxonomy in `intelligence/api_top10.json`
  (API1–API10 identifiers and risk names).

## OWASP Top 10 + ASVS

- **Sources:** https://github.com/OWASP/Top10 · https://github.com/OWASP/ASVS
- **License:** CC BY-SA 4.0
- **Used for:** the 2021 web risk taxonomy in `intelligence/owasp_top10.json`
  (A01–A10 identifiers) and the ASVS verification-area names in
  `intelligence/asvs.json` (V1–V14).

## MITRE CWE (Common Weakness Enumeration)

- **Source:** https://cwe.mitre.org
- **Used for:** standard weakness identifiers + names in `intelligence/cwe_map.json`
  (CWE IDs are MITRE's taxonomy; the technique→CWE mapping is our own).

---

All other code, chains, and data in this project are written by shinthink
(Blitz Strike), under the MIT license.
