- id: cb-xxe-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
$xml = $_GET['xml'];
$doc = simplexml_load_string($xml);
```
