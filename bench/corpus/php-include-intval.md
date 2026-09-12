- id: php-include-intval
- language: php
- vulnerable: false
- sink_type: file_inclusion
```php
<?php
$id = $_GET["id"];
include("/pages/" . intval($id) . ".php");
```
