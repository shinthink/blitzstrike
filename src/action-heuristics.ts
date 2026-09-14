/** Action-Name Heuristic Engine — the "what to look for WHERE" targeting layer.
 *
 *  A WordPress AJAX action NAME is a strong, data-driven signal for what
 *  vulnerability class to hunt. `*_upload*`/`*_import*` actions are prime
 *  arbitrary-file-upload → RCE; `*_delete*`/`*_write*` are file-write/delete;
 *  `*_load*`/`*_download*` are LFI; `*_login*`/`*_reset*` are auth-bypass; etc.
 *
 *  This module turns that into an ACTIVE engine (not a static reference):
 *  extract every `wp_ajax_*` action, map it to its vuln class, cross-reference
 *  the hook (nopriv?) + authz gap (nonce/capability present?), and emit a
 *  DERIVED priority — so the scanner targets the most dangerous action first.
 *  The mapping + examples are DATA; the priority is derived, never hardcoded.
 */

interface ActionHeuristic {
  pattern: RegExp;
  vuln_class: string;
  detector: string;
  /** Derived weight — how strongly this name pattern implies a real vuln. */
  weight: number;
  examples: string[];
}

const ACTION_HEURISTICS: ActionHeuristic[] = [
  { pattern: /upload|import|install|activate|plugin|theme/, vuln_class: "Arbitrary File Upload / Plugin Install → RCE", detector: "file_upload + missing_authz", weight: 0.9, examples: ["backup_import", "demo_upload_import_files", "template_import_install_package", "slider_upload"] },
  { pattern: /write|save|delete|remove|move|rename/, vuln_class: "Arbitrary File Write / Delete / Move", detector: "file_operations", weight: 0.8, examples: ["backup_delete"] },
  { pattern: /load|include|template|file|download|read/, vuln_class: "LFI / Path Traversal / RFI", detector: "path_traversal + file_inclusion", weight: 0.8, examples: ["backup_download", "get_file", "preview"] },
  { pattern: /exec|run|cmd|shell|eval|code/, vuln_class: "OS Command / Code Injection / eval", detector: "command_execution + code_execution", weight: 0.85, examples: [] },
  { pattern: /import|unserialize|restore|data/, vuln_class: "Insecure Deserialization / Object Injection", detector: "deserialization", weight: 0.8, examples: [] },
  { pattern: /query|search|filter|export|list/, vuln_class: "SQLi → RCE / Create Admin", detector: "sql_execution", weight: 0.7, examples: [] },
  { pattern: /render|shortcode|block|preview/, vuln_class: "SSTI / Shortcode / Block Injection", detector: "ssti", weight: 0.6, examples: [] },
  { pattern: /settings|option|update/, vuln_class: "Unauth Options Update / Settings Change / Missing Cap+Nonce", detector: "missing_authz + missing_nonce", weight: 0.85, examples: ["shop_settings_update", "builder_save"] },
  { pattern: /login|auth|token|reset|verify/, vuln_class: "Auth Bypass / Auto Login / Account Takeover", detector: "missing_authz + type_juggling", weight: 0.9, examples: ["auto-login", "magic link", "reset password"] },
  { pattern: /role|capability|promote|change_role/, vuln_class: "Privilege Escalation", detector: "missing_authz", weight: 0.9, examples: [] },
  { pattern: /register|signup|create_user/, vuln_class: "Register → RCE / AFU / PrivEsc", detector: "file_upload + missing_authz", weight: 0.8, examples: [] },
];

/** Map an action name to its most-likely vuln class (first matching heuristic). */
export function mapActionToVuln(action: string): { vuln_class: string; detector: string; weight: number; examples: string[] } | null {
  const a = action.toLowerCase();
  for (const h of ACTION_HEURISTICS) {
    if (h.pattern.test(a)) {
      return { vuln_class: h.vuln_class, detector: h.detector, weight: h.weight, examples: h.examples };
    }
  }
  return null;
}

export interface ActionSurfaceEntry {
  hook: string;
  action: string;
  nopriv: boolean;
  vuln_class: string;
  detector: string;
  examples: string[];
  has_capability: boolean;
  has_nonce: boolean;
  priority: number; // derived 0..1
}

/** Extract every wp_ajax_* action + cross-reference its authz gap + map to a
 *  vuln class, returning the prioritized attack surface. */
export function actionSurface(code: string): Record<string, unknown> {
  const entries: ActionSurfaceEntry[] = [];

  const ajaxRe = /add_action\s*\(\s*['"](wp_ajax(?:_nopriv)?_\w+)['"]\s*,\s*['"](\w+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = ajaxRe.exec(code)) !== null) {
    const hook = m[1];
    const handler = m[2];
    const nopriv = hook.startsWith("wp_ajax_nopriv_");
    const action = hook.replace(/^wp_ajax(?:_nopriv)?_/, "");
    const mapped = mapActionToVuln(action);
    if (!mapped) continue;

    // Find the handler body to cross-reference authz/nonce.
    const body = functionBody(code, handler);
    const hasCapability = body ? /current_user_can|is_user_logged_in|authorize/.test(body) : false;
    const hasNonce = body ? /wp_verify_nonce|check_ajax_referer|check_admin_referer|verify_nonce/.test(body) : false;

    // DERIVED priority: the vuln-class weight, boosted by an unauthenticated
    // hook + a missing capability/nonce check. All factors are data, not guesses.
    let priority = mapped.weight;
    if (nopriv) priority += 0.05;
    if (!hasCapability) priority += 0.05;
    if (!hasNonce) priority += 0.05;
    priority = Math.min(1, Number(priority.toFixed(2)));

    entries.push({
      hook, action, nopriv,
      vuln_class: mapped.vuln_class,
      detector: mapped.detector,
      examples: mapped.examples,
      has_capability: hasCapability,
      has_nonce: hasNonce,
      priority,
    });
  }

  entries.sort((a, b) => b.priority - a.priority);

  return {
    actions: entries.length,
    prioritized: entries.map((e) => ({
      action: e.action,
      hook: e.hook,
      vuln_class: e.vuln_class,
      detector: e.detector,
      priority: e.priority,
      nopriv: e.nopriv,
      has_capability: e.has_capability,
      has_nonce: e.has_nonce,
      examples: e.examples,
    })),
    top_priority: entries[0] ?? null,
  };
}

function functionBody(code: string, name: string): string | null {
  const idx = code.search(new RegExp(`function\\s+${name}\\s*\\(`));
  if (idx === -1) return null;
  const open = code.indexOf("{", idx);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") {
      depth--;
      if (depth === 0) return code.slice(open, i + 1);
    }
  }
  return code.slice(open);
}
