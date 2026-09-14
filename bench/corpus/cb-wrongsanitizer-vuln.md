- id: cb-wrongsanitizer-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$name = sanitize_text_field($_GET['name']);
$wpdb->query("SELECT * FROM users WHERE name = '$name'");
```
