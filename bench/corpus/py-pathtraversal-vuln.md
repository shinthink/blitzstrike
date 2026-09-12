- id: py-pathtraversal-vuln
- language: python
- vulnerable: true
- sink_type: file_operations
```python
f = request.args.get("file")
open("/data/" + f)
```
