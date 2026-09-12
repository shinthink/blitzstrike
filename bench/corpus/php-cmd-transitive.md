- id: php-cmd-transitive
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
function a($v) { b($v); }
function b($v) { system($v); }
a($_GET["cmd"]);
```
