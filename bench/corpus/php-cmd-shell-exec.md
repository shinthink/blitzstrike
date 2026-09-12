- id: php-cmd-shell-exec
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
$cmd = $_GET["cmd"];
shell_exec($cmd);
```
