- id: php-include-once
- language: php
- vulnerable: true
- sink_type: file_inclusion
```php
<?php
$page = $_GET["page"];
include_once($page . ".php");
```
