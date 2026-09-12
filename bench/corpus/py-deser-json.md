- id: py-deser-json
- language: python
- vulnerable: false
- sink_type: deserialization
```python
import json
data = request.get_data()
json.loads(data)
```
