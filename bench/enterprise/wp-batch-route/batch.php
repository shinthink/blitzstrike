<?php
/**
 * REST API batch endpoint (simplified) — forwards to inner handlers.
 *
 * The `/batch` route is registered WITHOUT a permission_callback, so it is
 * reachable unauthenticated. A malformed nested request desynchronizes the
 * batch router, letting an attacker reach handlers they should not.
 */

add_action('rest_api_init', function () {
    register_rest_route('my/v1', '/batch', array(
        'methods'             => 'POST',
        'callback'            => 'handle_batch',
        'permission_callback' => '__return_true', // <-- no real authz check
    ));
});

function handle_batch($request) {
    $operations = $request['requests'];
    $responses  = array();

    foreach ($operations as $op) {
        $route    = $op['route'];
        $handler  = resolve_route($route);
        $responses[] = $handler($op['params']);
    }

    return $responses;
}

function resolve_route($route) {
    $registry = array(
        'users'   => 'get_users',
        'posts'   => 'get_posts',
        'options' => 'get_options',
    );
    return $registry[$route];
}

function get_users($params) {
    global $wpdb;
    return $wpdb->get_results("SELECT * FROM users WHERE id = " . $params['id']);
}
