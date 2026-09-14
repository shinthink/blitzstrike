# Verification: privilege escalation (cross-file role change)

- **Detector:** `cross_file` → `priv_esc`
- **Target:** a membership/community plugin (PHP), source directory
- **Ground truth:** CVE-2023-3460 — `set_role($user_id, sanitize_key($_POST['role']))`
  reachable from the public registration flow with no capability check.
- **Result:** TP — 6 findings surfaced (was 0 before the detector).

## Evidence

The sink `set_role($user_id, sanitize_key($_POST['role']))` is in a user-model class;
the public entry point is a registration hook in another file. The reverse call-graph
traces the sink up to the public entry with no `current_user_can` on the chain.

## Notes

- Enabling fix: `sanitize_key` downgraded from "validated" to "sanitized" in the
  sanitizer lattice — `sanitize_key('administrator')` is still `administrator`, so it
  does NOT neutralize a role value.
- Cross-file is the root: the sink and the public entry are in different files, so a
  per-file detector misses it entirely.
