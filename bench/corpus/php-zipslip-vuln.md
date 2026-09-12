- id: php-zipslip-vuln
- language: php
- vulnerable: true
- sink_type: archive_extraction
```php
<?php
$dest = $_GET["dest"];
$zip = new ZipArchive();
$zip->extractTo($dest);
```
