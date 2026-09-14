- id: cb-secondorder-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$row = $wpdb->get_results("SELECT name FROM users");
echo $row->name;

```
