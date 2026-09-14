- id: rc-method-vuln
- language: php
- vulnerable: true
- detector: route_confusion

```php
<?php
$m = $_GET['m'];
$obj->$m();
```
