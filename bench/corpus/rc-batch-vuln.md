- id: rc-batch-vuln
- language: php
- vulnerable: true
- detector: route_confusion

```php
<?php
foreach ($requests as $r) { forward($r); }
```
