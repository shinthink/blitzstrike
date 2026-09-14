- id: cb-authz-safe
- language: php
- vulnerable: false
- detector: complex_bugs

```php
<?php
add_action('wp_ajax_delete_user', 'safe_handler');
function safe_handler() {
    check_ajax_referer('nonce');
    if (!current_user_can('manage_options')) { wp_die('no'); }
    $id = intval($_POST['id']);
    $wpdb->query($wpdb->prepare("DELETE FROM users WHERE id=%d", $id));
}
```
