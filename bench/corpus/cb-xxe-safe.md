- id: cb-xxe-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
$xml = $_GET['xml'];
libxml_disable_entity_loader(true);
$doc = simplexml_load_string($xml);
```
