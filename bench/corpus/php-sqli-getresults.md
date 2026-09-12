- id: php-sqli-getresults
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
$wpdb->get_results("SELECT * FROM t WHERE id=$id");
```
