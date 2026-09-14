- id: rc-dispatch-vuln
- language: php
- vulnerable: true
- detector: route_confusion

```php
<?php
call_user_func($_GET['callback']);
```
