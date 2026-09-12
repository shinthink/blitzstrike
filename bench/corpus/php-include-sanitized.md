- id: php-include-sanitized
- language: php
- vulnerable: false
- sink_type: file_inclusion
```php
<?php
$f = $_GET["f"];
include(sanitize_file_name($f));
```
