- id: java-sqli-prep
- language: java
- vulnerable: false
- sink_type: sql_execution
```java
String id = request.getParameter("id");
PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");
ps.setString(1, id);
```
