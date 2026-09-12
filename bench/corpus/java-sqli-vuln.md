- id: java-sqli-vuln
- language: java
- vulnerable: true
- sink_type: sql_execution
```java
String id = request.getParameter("id");
Statement st = conn.createStatement();
st.executeQuery("SELECT * FROM t WHERE id=" + id);
```
