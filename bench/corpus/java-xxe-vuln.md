- id: java-xxe-vuln
- language: java
- vulnerable: true
- sink_type: xml_processing
```java
InputStream in = request.getInputStream();
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
db.parse(in);
```
