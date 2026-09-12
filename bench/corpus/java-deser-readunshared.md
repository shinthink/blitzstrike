- id: java-deser-readunshared
- language: java
- vulnerable: true
- sink_type: deserialization
```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
ois.readUnshared();
```
