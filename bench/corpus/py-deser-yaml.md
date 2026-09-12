- id: py-deser-yaml
- language: python
- vulnerable: true
- sink_type: deserialization
```python
import yaml
data = request.get_data()
yaml.load(data)
```
