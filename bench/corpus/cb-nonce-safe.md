- id: cb-nonce-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
add_action("wp_ajax_delete", "del");
function del() { check_ajax_referer("del"); update_option("x", $_POST["v"]); }

```
