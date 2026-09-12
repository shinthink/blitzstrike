- id: php-xss-sanitizetext
- language: php
- vulnerable: false
- sink_type: html_render
```php
<?php
$v = $_GET["v"];
echo sanitize_text_field($v);
```
