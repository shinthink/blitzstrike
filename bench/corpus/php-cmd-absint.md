- id: php-cmd-absint
- language: php
- vulnerable: false
- sink_type: command_execution
```php
<?php
$n = $_GET["n"];
system("ping -c " . absint($n));
```
