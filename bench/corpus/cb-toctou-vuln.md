- id: cb-toctou-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
if (file_exists($f)) { unlink($f); }

```
