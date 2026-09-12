- id: js-xss-vuln
- language: javascript
- vulnerable: true
- sink_type: html_render
```javascript
const x = req.query.x;
res.send(x);
```
