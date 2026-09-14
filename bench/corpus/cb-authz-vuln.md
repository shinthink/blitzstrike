- id: cb-authz-vuln
- language: php
- vulnerable: true
- detector: complex_bugs

```php
<?php
add_action('wp_ajax_nopriv_delete_user', 'delete_user_handler');
function delete_user_handler() {
    $id = $_POST['id'];
    $wpdb->query("DELETE FROM users WHERE id=$id");
}
```
