- id: js-ssrf-vuln
- language: javascript
- vulnerable: true
- sink_type: http_request
```javascript
const u = req.query.url;
http.get(u, cb);
```
