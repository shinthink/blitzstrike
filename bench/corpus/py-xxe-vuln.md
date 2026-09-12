- id: py-xxe-vuln
- language: python
- vulnerable: true
- sink_type: xml_processing
```python
xml = request.data
etree.parse(xml)
```
