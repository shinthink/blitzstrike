- id: php-xss-ternary
- language: php
- vulnerable: true
- sink_type: html_render
```php
<?php
$t = isset($_GET["t"]) ? $_GET["t"] : "safe";
echo $t;
```
