- id: php-sqli-authgated
- language: php
- vulnerable: true
- sink_type: sql_execution
```php
<?php
function del($id) { if (current_user_can("x")) { global $wpdb; $wpdb->query("DELETE FROM t WHERE id=$id"); } }
del($_GET["id"]);
```
