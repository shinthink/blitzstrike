- id: php-fileupload-sanitized
- language: php
- vulnerable: false
- sink_type: file_operations
```php
<?php
$f = $_FILES["u"];
move_uploaded_file($f["tmp_name"], "/uploads/" . sanitize_file_name($f["name"]));
```
