- id: php-codeexec-assert
- language: php
- vulnerable: true
- sink_type: code_execution
```php
<?php
$code = $_GET["code"];
assert($code);
```
