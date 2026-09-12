- id: php-ssrf-wppost
- language: php
- vulnerable: true
- sink_type: http_request
```php
<?php
$url = $_GET["url"];
wp_remote_post($url, []);
```
