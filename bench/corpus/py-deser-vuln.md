- id: py-deser-vuln
- language: python
- vulnerable: true
- sink_type: deserialization
```python
import pickle
data = request.get_data()
pickle.loads(data)
```
