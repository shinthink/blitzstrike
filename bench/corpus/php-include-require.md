- id: php-include-require
- language: php
- vulnerable: true
- sink_type: file_inclusion
```php
<?php
$m = $_GET["m"];
require($m . ".php");
```
