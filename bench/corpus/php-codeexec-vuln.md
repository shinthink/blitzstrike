- id: php-codeexec-vuln
- language: php
- vulnerable: true
- sink_type: code_execution
```php
<?php
$code = $_GET["code"];
eval($code);
```
