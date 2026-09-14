- id: cb-pathconf-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$f = $_GET['file'];
echo file_get_contents($f);
```
