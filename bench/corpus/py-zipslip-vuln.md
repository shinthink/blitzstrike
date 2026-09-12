- id: py-zipslip-vuln
- language: python
- vulnerable: true
- sink_type: archive_extraction
```python
dest = request.args.get("dest")
zf.extractall(dest)
```
