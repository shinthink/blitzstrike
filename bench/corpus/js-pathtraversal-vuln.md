- id: js-pathtraversal-vuln
- language: javascript
- vulnerable: true
- sink_type: file_operations
```javascript
const f = req.query.file;
fs.readFile("/data/" + f);
```
