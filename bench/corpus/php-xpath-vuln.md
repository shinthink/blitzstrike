- id: php-xpath-vuln
- language: php
- vulnerable: true
- sink_type: xpath_injection
```php
<?php
$q = $_GET["q"];
$res = $doc->xpath($q);
```
