- id: php-unserialize-vuln
- language: php
- vulnerable: true
- sink_type: deserialization
```php
<?php
$data = $_COOKIE["data"];
unserialize($data);
```
