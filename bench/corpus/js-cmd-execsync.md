- id: js-cmd-execsync
- language: javascript
- vulnerable: true
- sink_type: command_execution
```javascript
const c = req.query.cmd;
execSync("ls " + c);
```
