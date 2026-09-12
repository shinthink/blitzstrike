- id: php-fileupload-name
- language: php
- vulnerable: true
- sink_type: file_operations
```php
<?php
$f = $_FILES["f"];
move_uploaded_file($f["tmp_name"], $f["name"]);
```
