- id: rc-dispatch-safe
- language: php
- vulnerable: false
- detector: route_confusion

```php
<?php
$cb = $_GET['cb'];
call_user_func($map[$cb]);
```
