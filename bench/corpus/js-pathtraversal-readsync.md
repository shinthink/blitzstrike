- id: js-pathtraversal-readsync
- language: javascript
- vulnerable: true
- sink_type: path_traversal
```javascript
const f = req.query.file;
fs.readFileSync("/data/" + f);
```
