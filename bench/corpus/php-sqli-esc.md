- id: php-sqli-esc
- language: php
- vulnerable: false
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
$q = $wpdb->query("SELECT * FROM t WHERE id=" . esc_sql($id));
```
