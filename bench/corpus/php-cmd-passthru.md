- id: php-cmd-passthru
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
$cmd = $_GET["cmd"];
passthru($cmd);
```
