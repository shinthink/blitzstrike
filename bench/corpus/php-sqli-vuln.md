- id: php-sqli-vuln
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
$wpdb->query("SELECT * FROM t WHERE id=$id");
```
