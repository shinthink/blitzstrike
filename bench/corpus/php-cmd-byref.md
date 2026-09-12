- id: php-cmd-byref
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
function fill(&$out) { $out = $_GET["cmd"]; }
$c = "";
fill($c);
system($c);
```
