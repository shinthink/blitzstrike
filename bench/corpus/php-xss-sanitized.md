- id: php-xss-sanitized
- language: php
- vulnerable: false
- sink_type: html_render
```php
<?php
$name = $_GET["name"];
echo htmlspecialchars($name);
```
