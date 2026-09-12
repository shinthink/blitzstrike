- id: js-sqli-param
- language: javascript
- vulnerable: false
- sink_type: sql_execution
```javascript
const id = req.query.id;
db.query("SELECT * FROM t WHERE id=?", [id]);
```
