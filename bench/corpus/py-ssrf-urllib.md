- id: py-ssrf-urllib
- language: python
- vulnerable: true
- sink_type: http_request
```python
import urllib.request
url = request.args.get("url")
urllib.request.urlopen(url)
```
