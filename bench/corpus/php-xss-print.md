- id: php-xss-print
- language: php
- vulnerable: true
- sink_type: html_render
```php
<?php
$name = $_GET["name"];
print $name;
```
