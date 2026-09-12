- id: php-sqli-interproc
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
function run_q($id) { global $wpdb; $wpdb->query("SELECT * FROM t WHERE id=$id"); }
$id = $_GET["id"];
run_q($id);
```
