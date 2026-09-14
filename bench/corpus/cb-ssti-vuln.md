- id: cb-ssti-vuln
- language: javascript
- vulnerable: true
- detector: complex_bugs

```js
const html = ejs.render(req.query.template);
```
