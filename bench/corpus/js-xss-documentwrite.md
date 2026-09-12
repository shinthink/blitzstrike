- id: js-xss-documentwrite
- language: javascript
- vulnerable: true
- sink_type: html_render
```javascript
const x = req.query.x;
document.write(x);
```
