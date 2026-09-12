- id: js-sqli-vuln
- language: javascript
- vulnerable: true
- sink_type: sql_execution
```javascript
const id = req.query.id;
db.query("SELECT * FROM t WHERE id=" + id);
```
