- id: java-xss-vuln
- language: java
- vulnerable: true
- sink_type: html_render
```java
String x = request.getParameter("x");
response.getWriter().write(x);
```
