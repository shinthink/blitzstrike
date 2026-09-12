- id: php-cmd-escaped
- language: php
- vulnerable: false
- sink_type: command_execution
```php
<?php
$cmd = $_GET["cmd"];
system(escapeshellarg($cmd));
```
