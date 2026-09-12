- id: java-xss-println
- language: java
- vulnerable: true
- sink_type: html_render
```java
String x = request.getParameter("x");
response.getWriter().println(x);
```
