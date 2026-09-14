- id: cb-deser-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$data = $_GET['data'];
$obj = unserialize($data);
class X { function __destruct() { system('id'); } }
```
