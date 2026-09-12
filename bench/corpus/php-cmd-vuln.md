- id: php-cmd-vuln
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
$cmd = $_GET["cmd"];
system($cmd);
```
