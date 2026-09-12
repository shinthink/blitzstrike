- id: py-cmd-vuln
- language: python
- vulnerable: true
- sink_type: command_execution
```python
import os
cmd = request.args.get("cmd")
os.system(cmd)
```
