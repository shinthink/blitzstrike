- id: js-xss-escape
- language: javascript
- vulnerable: false
- sink_type: html_render
```javascript
const x = req.query.x;
res.send(escapeHtml(x));
```
