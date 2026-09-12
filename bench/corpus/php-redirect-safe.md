- id: php-redirect-safe
- language: php
- vulnerable: false
- sink_type: redirect
```php
<?php
$url = $_GET["url"];
wp_safe_redirect($url);
```
