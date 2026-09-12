- id: java-cmd-vuln
- language: java
- vulnerable: true
- sink_type: command_execution
```java
String cmd = request.getParameter("cmd");
Runtime.getRuntime().exec(cmd);
```
