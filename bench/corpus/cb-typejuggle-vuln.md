- id: cb-typejuggle-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
if ($_GET['password'] == $secret) { echo 'ok'; }
```
