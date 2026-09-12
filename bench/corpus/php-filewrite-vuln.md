- id: php-filewrite-vuln
- language: php
- vulnerable: true
- sink_type: file_operations
```php
<?php
$data = $_POST["data"];
file_put_contents("/tmp/log.txt", $data);
```
