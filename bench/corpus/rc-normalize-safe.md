- id: rc-normalize-safe
- language: php
- vulnerable: false
- detector: route_confusion

```php
<?php
$path = $_GET['p'];
if (preg_match("/^[a-z]+$/", $path)) route($path);
```
