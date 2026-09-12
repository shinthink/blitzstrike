- id: php-sqli-filter
- language: php
- vulnerable: false
- sink_type: sql_execution
```php
<?php
$id = filter_var($_GET["id"], FILTER_VALIDATE_INT);
$wpdb->query("SELECT * FROM t WHERE id=$id");
```
