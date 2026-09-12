- id: js-cmd-spawn
- language: javascript
- vulnerable: false
- sink_type: command_execution
```javascript
const c = req.query.cmd;
spawn("ls", [c]);
```
