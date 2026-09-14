- id: rc-include-vuln
- language: php
- vulnerable: true
- detector: route_confusion

```php
<?php
include($_GET['page']);
```
