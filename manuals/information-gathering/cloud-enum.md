# cloud_enum

- **Category**: Information Gathering / Cloud Asset Discovery
- **Risk Level**: 🟢 Low

---

## Description

cloud_enum is a multi-cloud OSINT tool for finding public cloud assets associated with a keyword or organization name. It checks common AWS, Azure, and Google Cloud storage and service naming patterns. Use it when cloud infrastructure is explicitly in scope and you need to discover public buckets, storage accounts, or app endpoints.

## Installation

```bash
sudo apt update
sudo apt install cloud-enum
cloud_enum -h
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-k <keyword>` | Keyword (can use argument multiple times) |
| `-kf <file>` | Input file with a single keyword per line |
| `-m <file>` | Custom mutations file (default: `enum_tools/fuzz.txt`) |
| `-b <file>` | Brute-force list for Azure container names (default: `enum_tools/fuzz.txt`) |
| `-t <n>` | Number of threads for HTTP brute-force (default: 5) |
| `-ns <server>` | DNS server to use in brute-force |
| `-l <logfile>` | Appends found items to specified file |
| `-f <format>` | Log file format: `text`, `json`, or `csv` (default: `text`) |
| `--disable-aws` | Disable Amazon checks |
| `--disable-azure` | Skip Azure checks |
| `--disable-gcp` | Disable Google checks |
| `-qs` | Quick scan: disable mutations and second-level scans |

## Common Commands

```bash
# Search for public cloud assets using one keyword
cloud_enum -k examplecorp

# Use multiple keywords
cloud_enum -kf keywords.txt -l /tmp/cloud-enum.log

# Search only AWS and Azure
cloud_enum -k examplecorp --disable-gcp

# Use generated organization variants
printf "examplecorp\\nexample-corp\\nexample\\n" > cloud-keywords.txt
cloud_enum -kf cloud-keywords.txt -l /tmp/cloud-assets.txt
```

## Notes & Tips

1. Only run cloud enumeration when cloud assets are included in the authorized scope.
2. Use multiple naming variants: company name, abbreviations, product names, and domain stem.
3. Public bucket discovery does not imply permission to access or download data; validate scope before deeper testing.
4. Pair findings with manual verification and screenshots or metadata in the report.

---

## Official References

- [cloud_enum GitHub](https://github.com/initstring/cloud_enum)
- [Kali cloud-enum](https://www.kali.org/tools/cloud-enum/)
