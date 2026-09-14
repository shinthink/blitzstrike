- id: cb-toctou-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
unlink($f);

```
