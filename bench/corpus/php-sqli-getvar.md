- id: php-sqli-getvar
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
$id = $_GET["id"];
$wpdb->get_var("SELECT name FROM t WHERE id=$id");
```
