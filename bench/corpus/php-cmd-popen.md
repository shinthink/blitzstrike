- id: php-cmd-popen
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
$cmd = $_GET["cmd"];
popen($cmd, "r");
```
