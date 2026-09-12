- id: java-ssrf-httpurl
- language: java
- vulnerable: true
- sink_type: http_request
```java
String url = request.getParameter("url");
HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
```
