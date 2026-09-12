- id: php-xss-return
- language: php
- vulnerable: true
- sink_type: html_render
```php
<?php
function id($x) { return $x; }
echo id($_GET["q"]);
```
