- id: php-xss-vuln
- language: php
- vulnerable: true
- sink_type: html_render
```php
<?php
$name = $_GET["name"];
echo $name;
```
