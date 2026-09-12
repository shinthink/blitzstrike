- id: php-fileupload-vuln
- language: php
- vulnerable: true
- sink_type: file_operations
```php
<?php
$f = $_FILES["u"];
move_uploaded_file($f["tmp_name"], "/uploads/" . $f["name"]);
```
