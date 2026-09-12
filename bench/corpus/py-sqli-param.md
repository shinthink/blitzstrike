- id: py-sqli-param
- language: python
- vulnerable: false
- sink_type: sql_execution
```python
import sqlite3
id = request.args.get("id")
cursor.execute("SELECT * FROM t WHERE id=?", (id,))
```
