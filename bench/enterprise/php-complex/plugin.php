<?php
/**
 * Plugin helper (simplified) with multiple complex-bug patterns.
 */

// 1. Deserialization → object injection (magic method present)
function restore_session($payload) {
    $data = $_POST['data'];
    $obj  = unserialize($data);
    return $obj;
}

class CacheManager {
    public function __destruct() {
        // Magic method — a POP gadget can pivot object injection to RCE here.
        system("rm -rf /tmp/cache");
    }
}

// 2. Type juggling — loose comparison of user input against a hash
function verify_signature() {
    $sig    = $_GET['sig'];
    $secret = get_option('signing_secret');
    if ($sig == $secret) {          // <-- loose == , 0e... collision bypass
        return true;
    }
    return false;
}

// 3. Mass assignment — extract() of request data without EXTR_SKIP
function bootstrap_options() {
    extract($_REQUEST);             // <-- variable injection
    return $admin;                  // $admin is attacker-controlled
}
