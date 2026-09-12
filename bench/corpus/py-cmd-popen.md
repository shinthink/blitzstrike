- id: py-cmd-popen
- language: python
- vulnerable: true
- sink_type: command_execution
```python
import os
cmd = request.args.get("cmd")
os.popen(cmd)
```
