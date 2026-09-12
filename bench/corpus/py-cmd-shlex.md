- id: py-cmd-shlex
- language: python
- vulnerable: false
- sink_type: command_execution
```python
import shlex, subprocess
cmd = request.args.get("cmd")
subprocess.run(shlex.quote(cmd))
```
