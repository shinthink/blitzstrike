- id: cb-wrongsanitizer-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
$name = esc_sql($_GET['name']);
$wpdb->query("SELECT * FROM users WHERE name = '$name'");
```
