- id: cb-massassign-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
extract($_POST, EXTR_SKIP);
```
