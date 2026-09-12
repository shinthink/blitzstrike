- id: php-ssrf-vuln
- language: php
- vulnerable: true
- sink_type: http_request
```php
<?php
$url = $_GET["url"];
file_get_contents($url);
```
