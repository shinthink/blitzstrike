- id: java-ssrf-vuln
- language: java
- vulnerable: true
- sink_type: http_request
```java
String url = request.getParameter("url");
URL u = new URL(url);
u.openConnection();
```
