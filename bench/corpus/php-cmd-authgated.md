- id: php-cmd-authgated
- language: php
- vulnerable: true
- sink_type: command_execution
```php
<?php
if (is_user_logged_in()) { system($_GET["c"]); }
```
