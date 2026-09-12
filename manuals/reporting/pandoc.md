# pandoc

- **Category**: Reporting / Document Format Conversion
- **Risk Level**: 🟢 Low

---

## Description

A universal document format conversion tool that supports bidirectional conversion between 40+ formats including Markdown, HTML, LaTeX, Word, and PDF. In penetration testing, it is commonly used to convert Markdown test notes into professional Word/PDF reports, and can be used with custom templates.

## Installation

```bash
sudo apt install pandoc
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-o <file>` | Output file |
| `--pdf-engine <engine>` | PDF rendering engine |
| `--toc` | Include table of contents |
| `-V <key>=<value>` | Template variable |
| `--reference-doc <file>` | Reference document for styling |

## Common Commands

```bash
# Markdown → PDF
pandoc report.md -o report.pdf
# Note: default PDF engine is pdflatex; install texlive if missing:
# sudo apt install texlive-latex-base

# Use wkhtmltopdf engine (better CSS/HTML style support, no LaTeX required)
# sudo apt install wkhtmltopdf
pandoc report.md -o report.pdf --pdf-engine=wkhtmltopdf

# Markdown → Word (.docx)
pandoc report.md -o report.docx

# Use a custom Word template
pandoc report.md --reference-doc=template.docx -o report.docx

# Markdown → HTML
pandoc report.md -o report.html --standalone --css=style.css
# Pandoc's default stylesheet includes max-width: 36em — remove it to use full page width
sed -i 's/max-width: 36em;//' report.html

# Merge multiple Markdown files
pandoc intro.md findings.md appendix.md -o full_report.pdf

# Add metadata (use -V for template variables, or YAML front matter in the .md file)
pandoc report.md -o report.pdf \
  -V title:"Penetration Test Report" \
  -V author:"Security Team" \
  -V date:"2024-01-01"
# Note: -M sets metadata variables; -V sets template variables. For most templates use -V.

# Generate PDF with table of contents
pandoc report.md -o report.pdf --toc --toc-depth=3
```

### Markdown Report Template for Penetration Testing

```bash
# Create a report template
cat > /tmp/report-template.md << 'EOF'
---
title: Penetration Test Report
author: Tester
date: $(date +%Y-%m-%d)
---

# Executive Summary

# Findings Summary

# Detailed Findings

# Appendices
EOF

# Convert to PDF
pandoc /tmp/report-template.md -o /tmp/report.pdf --pdf-engine=wkhtmltopdf
```

## Notes & Tips

1. The default PDF engine (`pdflatex`) requires `texlive-latex-base` — use `--pdf-engine=wkhtmltopdf` for simpler HTML-based PDF rendering without LaTeX.
2. Use a custom Word template (`--reference-doc=template.docx`) to match client branding — extract the default template with `pandoc -o template.docx --print-default-data-file reference.docx`.
3. YAML front matter in the Markdown file sets document metadata (title, author, date) without needing `-V` flags on the command line. **Always use front matter instead of `--metadata title=` when the title contains non-ASCII characters** — passing CJK or other multibyte text via command-line arguments through SSH/expect causes encoding corruption in the generated `<title>` tag.
4. Merge multiple Markdown files in one command — pass them in order: `pandoc recon.md scanning.md findings.md -o report.pdf`.
5. Use `--toc --toc-depth=3` to automatically generate a linked table of contents in both PDF and Word output.

---

## Official References

- [Pandoc Official Site](https://pandoc.org/)
- [Pandoc User's Guide](https://pandoc.org/MANUAL.html)
