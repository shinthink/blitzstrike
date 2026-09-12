- id: js-redirect-vuln
- language: javascript
- vulnerable: true
- sink_type: redirect
```javascript
const u = req.query.url;
res.redirect(u);
```
