- id: php-include-whitelist
- language: php
- vulnerable: false
- sink_type: file_inclusion
```php
<?php
$page = $_GET["page"];
$allow = ["home", "about"];
if (in_array($page, $allow)) { include($page . ".php"); }
```
