- id: py-cmd-subprocess
- language: python
- vulnerable: false
- sink_type: command_execution
```python
import subprocess
cmd = request.args.get("cmd")
subprocess.run(["ls", cmd])
```
