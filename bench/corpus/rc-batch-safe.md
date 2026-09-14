- id: rc-batch-safe
- language: php
- vulnerable: false
- detector: route_confusion

```php
<?php
foreach ($requests as $r) { if (!authorize($r)) continue; handle($r); }
```
