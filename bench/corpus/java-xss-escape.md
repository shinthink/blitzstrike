- id: java-xss-escape
- language: java
- vulnerable: false
- sink_type: html_render
```java
String x = request.getParameter("x");
response.getWriter().write(HtmlUtils.htmlEscape(x));
```
