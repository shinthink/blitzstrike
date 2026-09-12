- id: php-include-vuln
- language: php
- vulnerable: true
- sink_type: file_inclusion
```php
<?php
$page = $_GET["page"];
include($page . ".php");
```
