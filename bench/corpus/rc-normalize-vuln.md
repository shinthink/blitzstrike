- id: rc-normalize-vuln
- language: php
- vulnerable: true
- detector: route_confusion

```php
<?php
$path = $_GET['p'];
if (preg_match("/^\/admin/", $path)) route($path);
```
