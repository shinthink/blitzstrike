- id: php-sqli-prepared
- language: php
- vulnerable: false
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
$wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id=%d", $id));
```
