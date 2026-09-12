- id: php-xss-eschtml
- language: php
- vulnerable: false
- sink_type: html_render
```php
<?php
$name = $_GET["name"];
echo esc_html($name);
```
