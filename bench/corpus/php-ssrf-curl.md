- id: php-ssrf-curl
- language: php
- vulnerable: true
- sink_type: http_request
```php
<?php
$u = $_GET["u"];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $u);
curl_exec($ch);
```
