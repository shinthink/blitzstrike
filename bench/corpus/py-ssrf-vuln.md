- id: py-ssrf-vuln
- language: python
- vulnerable: true
- sink_type: http_request
```python
import requests
url = request.args.get("url")
requests.get(url)
```
