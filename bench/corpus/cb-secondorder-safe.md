- id: cb-secondorder-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
$row = $wpdb->get_results("SELECT name FROM users");
echo esc_html($row->name);

```
