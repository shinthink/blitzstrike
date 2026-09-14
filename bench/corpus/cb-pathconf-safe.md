- id: cb-pathconf-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
$f = basename($_GET['file']);
echo file_get_contents($f);
```
