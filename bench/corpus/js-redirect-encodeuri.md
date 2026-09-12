- id: js-redirect-encodeuri
- language: javascript
- vulnerable: false
- sink_type: redirect
```javascript
const u = req.query.u;
res.redirect(encodeURIComponent(u));
```
