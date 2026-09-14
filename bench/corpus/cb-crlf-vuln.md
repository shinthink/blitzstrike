- id: cb-crlf-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
header("Location: " . $_GET['url']);
```
