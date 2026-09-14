- id: rc-method-safe
- language: php
- vulnerable: false
- detector: route_confusion

```php
<?php
$m = $_GET['m'];
$obj->{$allowed[$m]}();
```
