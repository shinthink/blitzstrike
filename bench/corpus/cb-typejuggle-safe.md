- id: cb-typejuggle-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
if ($_GET['password'] === $secret) { echo 'ok'; }
```
