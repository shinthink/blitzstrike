- id: cb-deser-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
$data = json_decode($_GET['data']);
```
