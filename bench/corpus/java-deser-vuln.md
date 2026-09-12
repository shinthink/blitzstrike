- id: java-deser-vuln
- language: java
- vulnerable: true
- sink_type: deserialization
```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
ois.readObject();
```
