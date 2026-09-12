- id: js-xss-innerhtml
- language: javascript
- vulnerable: true
- sink_type: html_render
```javascript
const x = req.query.x;
el.innerHTML = x;
```
