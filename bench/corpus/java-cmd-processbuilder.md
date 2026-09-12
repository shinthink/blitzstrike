- id: java-cmd-processbuilder
- language: java
- vulnerable: true
- sink_type: command_execution
```java
String cmd = request.getParameter("cmd");
new ProcessBuilder(cmd).start();
```
