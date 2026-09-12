<?php
/**
 * Hermetic fixture for the scanner/orchestrator regression checks.
 * Contains an unauth entry point + a dangerous upload sink so that
 * iterSourceFiles / scanFile / grepInFunctions / enrichScan / runEngagement
 * have a deterministic target that works in CI (no external path).
 */
function handle_upload($file) {
    $name = $file["name"];
    move_uploaded_file($file["tmp_name"], "/var/www/uploads/" . $name);
    return $name;
}

add_action("wp_ajax_nopriv_upload", "handle_upload");
