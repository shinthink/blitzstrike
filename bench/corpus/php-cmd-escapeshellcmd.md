- id: php-cmd-escapeshellcmd
- language: php
- vulnerable: false
- sink_type: command_execution
```php
<?php
$c = $_GET["c"];
system(escapeshellcmd($c));
```
