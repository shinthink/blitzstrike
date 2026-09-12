- id: js-ssrf-axios
- language: javascript
- vulnerable: true
- sink_type: http_request
```javascript
const u = req.query.url;
axios.get(u);
```
