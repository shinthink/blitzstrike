- id: py-sqli-executescript
- language: python
- vulnerable: true
- sink_type: sql_execution
```python
import sqlite3
id = request.args.get("id")
cursor.executescript(f"DELETE FROM t WHERE id={id}")
```
