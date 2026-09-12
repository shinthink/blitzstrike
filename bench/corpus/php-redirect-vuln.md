- id: php-redirect-vuln
- language: php
- vulnerable: true
- sink_type: redirect
```php
<?php
$url = $_GET["url"];
header("Location: " . $url);
```
