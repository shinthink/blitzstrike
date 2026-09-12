- id: php-deser-json
- language: php
- vulnerable: false
- sink_type: deserialization
```php
<?php
$data = $_COOKIE["data"];
json_decode($data);
```
