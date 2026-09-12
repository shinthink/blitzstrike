# ExifTool

- **Category**: Forensics / Metadata Analysis
- **Risk Level**: 🟢 Low

---

## Description

A powerful tool for reading and modifying file metadata, supporting 200+ file formats (images, PDFs, Office documents, video, audio, etc.). Extracts GPS coordinates, capture device information, timestamps, and more from images; extracts author information, revision history, and more from Office documents. Widely used in forensics and OSINT.

## Installation

```bash
sudo apt install libimage-exiftool-perl
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-TAG` | Read the specified tag (e.g., `-GPSLatitude`) |
| `-TAG=VALUE` | Set tag value (leave empty to delete the tag) |
| `-all=` | Remove all metadata |
| `-csv` | CSV format output |
| `-json` | JSON format output |
| `-r` | Recursive directory processing |
| `-if EXPR` | Conditional filter (e.g., `-if '$GPSLatitude'`) |
| `-ext EXT` | Process only files with the specified extension |
| `-overwrite_original` | Overwrite the original file (no backup) |

## Common Commands

```bash
# Read all metadata
exiftool image.jpg

# Extract specific fields
exiftool -GPSLatitude -GPSLongitude image.jpg
exiftool -Author -Creator document.pdf

# Batch process a directory
exiftool /tmp/images/

# Recursive processing
exiftool -r /tmp/downloads/

# CSV output (convenient for analysis)
exiftool -csv /tmp/images/ > /tmp/metadata.csv

# Modify metadata (remove GPS information)
exiftool -GPSLatitude= -GPSLongitude= image.jpg

# Remove all metadata
exiftool -all= document.pdf

# Extract author information from a PDF (for OSINT)
exiftool -Author document.pdf

# Find images that contain GPS data
exiftool -if '$GPSLatitude' -GPSLatitude -FileName -r /tmp/photos/
```

## Notes & Tips

1. Always work on a copy of evidence files — use `-overwrite_original` only when you intentionally want to modify the source.
2. GPS coordinates in EXIF data can be converted to Google Maps links such as `https://maps.google.com/?q=<lat>,<lon>`
3. Use `-csv` output for bulk metadata analysis across directories — easily importable into spreadsheets or Python pandas.
4. Many social media platforms strip EXIF data on upload; metadata is most likely to be present in images shared directly (email, cloud links, Dropbox).
5. For OSINT, `exiftool -Author -Creator -Producer -Company` reveals software versions, internal usernames, and organization names embedded in Office documents and PDFs.

---

## Official References

- [ExifTool Official Site](https://exiftool.org/)
- [ExifTool Application Documentation](https://exiftool.org/exiftool_pod.html)
- [ExifTool Tag Names Reference](https://exiftool.org/TagNames/)
- [ExifTool (GitHub)](https://github.com/exiftool/exiftool)
