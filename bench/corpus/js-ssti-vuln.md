- id: js-ssti-vuln
- language: javascript
- vulnerable: true
- sink_type: template_injection
```javascript
const tpl = req.query.tpl;
ejs.render(tpl, {});
```
