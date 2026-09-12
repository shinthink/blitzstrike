- id: js-cmd-vuln
- language: javascript
- vulnerable: true
- sink_type: command_execution
```javascript
const c = req.query.cmd;
exec("ls " + c);
```
