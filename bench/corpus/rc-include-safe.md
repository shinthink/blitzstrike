- id: rc-include-safe
- language: php
- vulnerable: false
- detector: route_confusion

```php
<?php
$f = basename($_GET['f']);
include($f);
```
