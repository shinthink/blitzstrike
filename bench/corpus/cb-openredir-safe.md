- id: cb-openredir-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
wp_safe_redirect($_GET["url"]);

```
