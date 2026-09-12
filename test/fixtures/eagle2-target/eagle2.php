<?php
// EAGLE-EYE 2.0 hermetic fixture: return propagation, byref alias, ternary,
// transitive interprocedural flow, sanitizer suppression, auth gating.

// Return propagation: helper returns its param; caller sinks the return.
function identity($x) { return $x; }

// Transitive inter-procedural: outer -> inner -> sink.
function inner_exec($v) { system($v); }
function outer_exec($v) { inner_exec($v); }

// By-reference alias: writes a source to the caller's variable.
function byref_fill(&$out) { $out = $_GET['r']; }

// Auth-gated sink (capability check).
function admin_delete($id) {
  if (current_user_can('manage_options')) {
    $wpdb->query("DELETE FROM t WHERE id=$id");
  }
}

// Unauth sink (no gate) — should be a finding.
function raw_delete($id) {
  $wpdb->query("DELETE FROM t WHERE id=$id");
}

// Top-level (main) scope
$u = identity($_GET['u']);
echo $u;                       // XSS via return propagation

$c = $_GET['c'];
outer_exec($c);                // command exec via transitive call

$ref = '';
byref_fill($ref);              // $ref tainted via byref alias
system($ref);                  // command exec via byref

$t = isset($_GET['t']) ? $_GET['t'] : 'safe';
echo $t;                       // XSS via ternary (tainted branch)

$q = $_GET['q'];
echo htmlspecialchars($q);     // SANITIZED -> suppressed (no finding)

admin_delete($_GET['a']);      // auth-gated SQLi (lower priority)
raw_delete($_GET['b']);        // unauth SQLi (finding)
