- id: php-xss-authgated
- language: php
- vulnerable: true
- sink_type: html_render
```php
<?php
if (current_user_can("edit")) { echo $_GET["x"]; }
```
