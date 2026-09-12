- id: php-ssrf-wpremote
- language: php
- vulnerable: true
- sink_type: http_request
```php
<?php
$url = $_GET["url"];
wp_remote_get($url);
```
