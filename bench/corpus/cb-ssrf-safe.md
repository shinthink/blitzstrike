- id: cb-ssrf-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
echo file_get_contents("https://api.example.com/" . $_GET['path']);
```
