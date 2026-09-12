- id: js-eval-vuln
- language: javascript
- vulnerable: true
- sink_type: code_execution
```javascript
const c = req.body.code;
eval(c);
```
