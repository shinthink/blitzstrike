- id: php-cmd-intval
- language: php
- vulnerable: false
- sink_type: command_execution
```php
<?php
$n = $_GET["n"];
system("ping -c " . intval($n));
```
