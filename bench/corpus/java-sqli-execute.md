- id: java-sqli-execute
- language: java
- vulnerable: true
- sink_type: sql_execution
```java
String id = request.getParameter("id");
st.execute("DELETE FROM t WHERE id=" + id);
```
