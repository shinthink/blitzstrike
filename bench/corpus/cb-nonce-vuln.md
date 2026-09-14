- id: cb-nonce-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
add_action("wp_ajax_delete", "del");
function del() { update_option("x", $_POST["v"]); }

```
