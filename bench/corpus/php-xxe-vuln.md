- id: php-xxe-vuln
- language: php
- vulnerable: true
- sink_type: xml_processing
```php
<?php
$xml = $_POST["xml"];
simplexml_load_string($xml);
```
