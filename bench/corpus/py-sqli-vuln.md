- id: py-sqli-vuln
- language: python
- vulnerable: true
- sink_type: sql_execution
```python
import sqlite3
id = request.args.get("id")
cursor.execute(f"SELECT * FROM t WHERE id={id}")
```
