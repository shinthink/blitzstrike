- id: php-xss-htmlentities
- language: php
- vulnerable: false
- sink_type: html_render
```php
<?php
$v = $_GET["v"];
echo htmlentities($v);
```
