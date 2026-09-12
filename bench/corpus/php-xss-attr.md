- id: php-xss-attr
- language: php
- vulnerable: false
- sink_type: html_render
```php
<?php
$v = $_GET["v"];
echo esc_attr($v);
```
