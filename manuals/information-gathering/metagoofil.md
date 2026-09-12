# Metagoofil

- **Category**: Information Gathering / OSINT
- **Risk Level**: 🟢

---

## Description

Metagoofil is an information gathering tool that searches Google for specific file types associated with a target domain and optionally downloads them for metadata extraction. It is useful during the reconnaissance phase to discover documents (PDF, DOC, XLS, PPT, etc.) published by an organization, which may contain metadata revealing usernames, software versions, internal paths, and other sensitive information.

## Installation

```bash
sudo apt install metagoofil
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-d DOMAIN` | Domain to search (required) |
| `-t FILE_TYPES` | File types to download: pdf, doc, xls, ppt, odp, ods, docx, xlsx, pptx, or "ALL" (required) |
| `-e DELAY` | Delay in seconds between searches (default: 30.0) |
| `-f [SAVE_FILE]` | Save the discovered HTML links to a file |
| `-i URL_TIMEOUT` | Seconds to wait before URL timeout (default: 15) |
| `-l SEARCH_MAX` | Maximum number of search results (default: 100) |
| `-n DOWNLOAD_FILE_LIMIT` | Maximum files to download per file type (default: 100) |
| `-o SAVE_DIRECTORY` | Directory to save downloaded files (default: current directory) |
| `-r NUMBER_OF_THREADS` | Number of downloader threads (default: 8) |
| `-u [USER_AGENT]` | User-Agent for file retrieval. `-u` alone randomizes, `-u "string"` sets custom |
| `-w` | Download the files instead of just viewing search results |

## Common Commands

### Scenario 1: Search for PDF and DOCX files on a domain

```bash
metagoofil -d example.com -t pdf,docx -l 50
```

### Scenario 2: Search and download all file types

```bash
metagoofil -d example.com -t ALL -w -o ./downloads/
```

### Scenario 3: Download PDFs with rate limiting

```bash
metagoofil -d example.com -t pdf -w -e 45 -n 20 -o ./loot/
```

### Scenario 4: Save discovered links to a file for later analysis

```bash
metagoofil -d example.com -t pdf,doc,xls,ppt -f links.html -l 200
```

### Scenario 5: Download with custom User-Agent and increased threads

```bash
metagoofil -d example.com -t pdf,docx,xlsx -w -u "Mozilla/5.0" -r 4 -o ./output/
```

### Scenario 6: Quick recon with randomized User-Agent

```bash
metagoofil -d example.com -t ALL -l 50 -u -f results.html
```

## Notes & Tips

1. The `-w` flag is required to actually download files. Without it, metagoofil only displays search results.
2. Use a reasonable delay (`-e`) between searches to avoid being blocked by Google. The default of 30 seconds is conservative but safe.
3. Downloaded files can be further analyzed with `exiftool` to extract metadata such as author names, software versions, and internal file paths.
4. Combine with tools like `FOCA` or manual `exiftool` analysis for comprehensive metadata extraction.
5. The "ALL" file type option covers: pdf, doc, xls, ppt, odp, ods, docx, xlsx, pptx.
6. Reduce `-n` (download limit) during initial recon to avoid downloading excessive files.
7. Google may rate-limit or CAPTCHA aggressive searches. Increase `-e` delay if you encounter issues.
8. Results depend on Google indexing; recently published or removed documents may not appear.

---

## Official References

- [Metagoofil - GitHub](https://github.com/opsdisk/metagoofil)
- [Metagoofil - Kali Tools](https://www.kali.org/tools/metagoofil/)
