- id: js-ssrf-fetch
- language: javascript
- vulnerable: true
- sink_type: http_request
```javascript
const u = req.query.url;
fetch(u);
```
