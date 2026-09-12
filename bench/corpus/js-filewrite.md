- id: js-filewrite
- language: javascript
- vulnerable: true
- sink_type: file_operations
```javascript
const d = req.body.data;
fs.writeFile("/tmp/x", d);
```
