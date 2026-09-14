- id: cb-ssrf-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$url = $_GET['url'];
echo file_get_contents($url);
```
