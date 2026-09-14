/** Framework Security Knowledge Graph — MULTI-FRAMEWORK security primitives
 *  encoded as DATA, powering the auth-bypass / CSRF detector.
 *
 *  Frameworks covered: WordPress, Laravel, Django, Flask, Express, Spring,
 *  Symfony, ASP.NET Core, Ruby on Rails. The knowledge is DATA (extensible);
 *  the detector is deterministic (pattern-based, no LLM guessing).
 */
import type { ComplexFinding } from "./complex-bugs.js";

// ---------------------------------------------------------------------------
// Knowledge graph — the framework primitives as data.
// ---------------------------------------------------------------------------

export interface FrameworkPrimitives {
  framework: string;
  auth_primitives: string[];
  nonce_primitives: string[];
  entry_point_hooks: string[];
  sanitizers: string[];
}

const FRAMEWORKS: Record<string, FrameworkPrimitives> = {
  wordpress: {
    framework: "wordpress",
    auth_primitives: ["current_user_can", "current_user_can_edit_post", "is_user_logged_in", "authorize"],
    nonce_primitives: ["wp_verify_nonce", "check_ajax_referer", "check_admin_referer", "verify_nonce"],
    entry_point_hooks: ["wp_ajax_", "wp_ajax_nopriv_", "admin_post_", "admin_post_nopriv_", "register_rest_route", "add_shortcode", "init", "rest_api_init"],
    sanitizers: ["sanitize_text_field", "esc_sql", "esc_html", "esc_attr", "esc_url", "wp_kses", "wp_kses_post", "absint", "sanitize_email", "sanitize_file_name"],
  },
  wp: {
    framework: "wordpress",
    auth_primitives: ["current_user_can", "is_user_logged_in", "authorize"],
    nonce_primitives: ["wp_verify_nonce", "check_ajax_referer", "check_admin_referer"],
    entry_point_hooks: ["wp_ajax_", "wp_ajax_nopriv_", "register_rest_route"],
    sanitizers: ["sanitize_text_field", "esc_sql", "esc_html", "absint"],
  },
  laravel: {
    framework: "laravel",
    auth_primitives: ["auth", "authorize", "Gate::", "can:", "->middleware('auth'", "->can(", "$this->authorize", "@can", "@cannot", "policy"],
    nonce_primitives: ["@csrf", "csrf_field", "VerifyCsrfToken"],
    entry_point_hooks: ["Route::get", "Route::post", "Route::put", "Route::delete", "Route::resource", "Route::match"],
    sanitizers: ["e(", "htmlspecialchars", "clean(", "strip_tags"],
  },
  django: {
    framework: "django",
    auth_primitives: ["login_required", "permission_required", "user_passes_test", "LoginRequiredMixin", "PermissionRequiredMixin", "permission_classes", "IsAuthenticated", "has_permission"],
    nonce_primitives: ["csrf_protect", "CsrfViewMiddleware", "@csrf"],
    entry_point_hooks: ["def ", "@api_view", "path(", "url(", "re_path("],
    sanitizers: ["escape(", "mark_safe", "html.escape"],
  },
  flask: {
    framework: "flask",
    auth_primitives: ["login_required", "@login_required", "current_user.is_authenticated", "permission_required"],
    nonce_primitives: ["CSRFProtect", "csrf_token"],
    entry_point_hooks: ["@app.route", "@blueprint.route", "@bp.route"],
    sanitizers: ["escape(", "Markup", "html.escape"],
  },
  express: {
    framework: "express",
    auth_primitives: ["requireAuth", "authenticate", "passport.authenticate", "req.user", "isAuthenticated", "ensureAuthenticated", "requireLogin", "authorize", "authMiddleware"],
    nonce_primitives: ["csurf", "csrfProtection", "helmet"],
    entry_point_hooks: ["app.get", "app.post", "router.get", "router.post"],
    sanitizers: ["escapeHtml", "encodeURIComponent", "sanitize", "xss"],
  },
  spring: {
    framework: "spring",
    auth_primitives: ["@PreAuthorize", "@Secured", "@RolesAllowed", "hasRole", "hasAuthority", "isAuthenticated", "SecurityContextHolder"],
    nonce_primitives: ["csrf", "CsrfToken"],
    entry_point_hooks: ["@GetMapping", "@PostMapping", "@RequestMapping", "@Controller"],
    sanitizers: ["HtmlUtils.htmlEscape", "escapeHtml", "StringEscapeUtils"],
  },
  symfony: {
    framework: "symfony",
    auth_primitives: ["is_granted", "denyAccessUnlessGranted", "->isGranted(", "IsGranted", "Voter"],
    nonce_primitives: ["isCsrfTokenValid", "csrf_token"],
    entry_point_hooks: ["#[Route", "@Route", "#[Get", "#[Post"],
    sanitizers: ["e(", "htmlspecialchars", "escape("],
  },
  aspnet: {
    framework: "aspnet",
    auth_primitives: ["[Authorize", "[AllowAnonymous", "User.Identity", "IsInRole", "AuthorizeAsync", "IAuthorizationService"],
    nonce_primitives: ["ValidateAntiForgeryToken", "Antiforgery"],
    entry_point_hooks: ["[HttpGet", "[HttpPost", "[Route("],
    sanitizers: ["HtmlEncoder", "Html.Raw", "UrlEncoder"],
  },
  rails: {
    framework: "rails",
    auth_primitives: ["authenticate_user!", "authorize", "before_action :authenticate", "before_action :authorize", "current_user"],
    nonce_primitives: ["protect_from_forgery", "form_authenticity_token"],
    entry_point_hooks: ["def ", "before_action"],
    sanitizers: ["h(", "html_escape", "sanitize"],
  },
};

export function frameworkKnowledge(framework = "wordpress"): FrameworkPrimitives | null {
  return FRAMEWORKS[framework.toLowerCase()] ?? null;
}

export function listFrameworks(): string[] {
  const s = new Set<string>();
  for (const k of Object.keys(FRAMEWORKS)) s.add(FRAMEWORKS[k].framework);
  return [...s];
}

// ---------------------------------------------------------------------------
// Detector — missing authorization / nonce on framework entry points.
// ---------------------------------------------------------------------------

function lineNoOf(code: string, pos: number): number {
  let n = 1;
  for (let i = 0; i < pos; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
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

/** Extract the handler name from `'fn'`, `array($this,'m')`, `array('C','m')`, or a closure. */
function handlerName(expr: string): string | null {
  const quoted = expr.match(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g);
  if (quoted && quoted.length > 0) return quoted[quoted.length - 1].replace(/['"]/g, "");
  return null;
}

// A call to an authorization-ish helper (indirect check) → don't flag.
const INDIRECT_AUTH = /\b[a-zA-Z0-9_]*(auth|permission|cap|nonce|can_|check|verify|allow)[a-zA-Z0-9_]*\s*\(/;

// The full capability/authorization surface (WordPress Code Reference). NOTE:
// `is_admin()` and `wp_doing_ajax()` are REQUEST-CONTEXT checks, NOT
// authorization — they return true regardless of the user's role, so they are
// deliberately excluded (treating them as auth causes false negatives).
const AUTH_RE = /current_user_can|is_user_logged_in|is_super_admin|current_user_can_edit_post|authorize/;
// The full nonce-verification surface.
const NONCE_RE = /wp_verify_nonce|check_ajax_referer|check_admin_referer|verify_nonce/;

// State-changing / privileged operations. Nonces guard CSRF (state changes) and
// capabilities guard privilege — so both missing_nonce and missing_authz only
// apply when the handler actually performs one of these. Read-only handlers
// (list/search/get) legitimately need neither.
const DANGEROUS_OP_RE = /\b(update_option|add_option|delete_option|update_site_option|delete_site_option|update_post_meta|add_post_meta|delete_post_meta|update_user_meta|add_user_meta|delete_user_meta|update_metadata|add_metadata|delete_metadata|set_transient|delete_transient|wp_insert_post|wp_update_post|wp_delete_post|wp_trash_post|wp_untrash_post|wp_insert_comment|wp_update_comment|wp_delete_comment|wp_insert_user|wp_update_user|wp_delete_user|wp_create_user|wp_set_current_user|wp_set_auth_cookie|set_user_role|set_role|add_role|remove_role|add_cap|remove_cap|wp_mail|wp_new_user_notification|wp_handle_upload|move_uploaded_file|wp_upload_bits|wp_set_object_terms|wp_set_post_terms|wp_schedule_event|wp_clear_scheduled_hook|wp_redirect|file_put_contents|unlink|rename|wpdb->query|wpdb->insert|wpdb->update|wpdb->delete|wpdb->replace)\s*\(/;

/** WordPress: AJAX / admin-post / REST entry points missing capability or nonce. */
function detectWpAuthz(code: string, file: string, out: ComplexFinding[]): void {
  const ajaxRe = /add_action\s*\(\s*['"](wp_ajax(?:_nopriv)?_\w+)['"]\s*,\s*(.+?)\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = ajaxRe.exec(code)) !== null) {
    const hook = m[1];
    const handler = handlerName(m[2]);
    if (!handler) continue;
    const nopriv = hook.startsWith("wp_ajax_nopriv_");
    const body = functionBody(code, handler);
    if (!body) continue;
    const hasCap = AUTH_RE.test(body) || INDIRECT_AUTH.test(body);
    const hasNonce = NONCE_RE.test(body);
    const dangerous = DANGEROUS_OP_RE.test(body);
    const line = lineNoOf(code, m.index);
    if (nopriv && !hasCap && dangerous) {
      out.push({ file, line, type: "missing_authz", category: "Missing capability check (unauthenticated AJAX handler)", severity: "high", evidence: `add_action('${hook}', ...)`, detail: `Unauthenticated AJAX handler '${handler}()' performs a privileged/state-changing operation with no current_user_can()/authorization check — auth bypass / privilege escalation.` });
    }
    if (!hasNonce && dangerous) {
      out.push({ file, line, type: "missing_nonce", category: "Missing nonce verification", severity: "medium", evidence: `add_action('${hook}', ...)`, detail: `AJAX handler '${handler}()' performs a state-changing operation without nonce verification (wp_verify_nonce / check_ajax_referer) — CSRF.` });
    }
  }

  const adminRe = /add_action\s*\(\s*['"](admin_post(?:_nopriv)?_\w+)['"]\s*,\s*(.+?)\s*\)/g;
  while ((m = adminRe.exec(code)) !== null) {
    const hook = m[1];
    const handler = handlerName(m[2]);
    if (!handler) continue;
    const nopriv = hook.startsWith("admin_post_nopriv_");
    const body = functionBody(code, handler);
    if (!body) continue;
    const hasCap = AUTH_RE.test(body) || INDIRECT_AUTH.test(body);
    const hasNonce = NONCE_RE.test(body);
    const dangerous = DANGEROUS_OP_RE.test(body);
    const line = lineNoOf(code, m.index);
    if (nopriv && !hasCap && dangerous) {
      out.push({ file, line, type: "missing_authz", category: "Missing capability check (unauthenticated admin-post handler)", severity: "high", evidence: `add_action('${hook}', ...)`, detail: `Unauthenticated admin-post handler '${handler}()' performs a privileged/state-changing operation with no authorization check — auth bypass / privilege escalation.` });
    }
    if (!hasNonce && dangerous) {
      out.push({ file, line, type: "missing_nonce", category: "Missing nonce verification", severity: "medium", evidence: `add_action('${hook}', ...)`, detail: `admin-post handler '${handler}()' performs a state-changing operation without nonce verification — CSRF.` });
    }
  }

  const restRe = /register_rest_route\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/g;
  while ((m = restRe.exec(code)) !== null) {
    const line = lineNoOf(code, m.index);
    const window = code.slice(m.index, m.index + 800);
    // permission_callback is OPTIONAL in WP core — when absent the route is
    // PUBLIC (default). `__return_true` is the explicit "public" marker, which
    // is still no real authorization check (and is where a dev comments out a
    // real `check_admin_permission` and substitutes `__return_true`).
    const pc = window.match(/permission_callback['"]?\s*=>\s*(.+?)(?:,|\s*\n|\])/);
    if (pc) {
      const expr = pc[1].trim();
      if (/__return_true/.test(expr)) {
        out.push({ file, line, type: "missing_authz", category: "REST route explicitly public (__return_true)", severity: "medium", evidence: `register_rest_route('${m[1]}', '${m[2]}')`, detail: `REST route '${m[1]}${m[2]}' sets permission_callback to __return_true (always allow) — verify the endpoint does not expose sensitive data or perform privileged actions.` });
      }
      // A real permission callback (function / method / current_user_can) → safe.
      continue;
    }
    out.push({ file, line, type: "missing_authz", category: "REST route missing permission_callback", severity: "high", evidence: `register_rest_route('${m[1]}', '${m[2]}')`, detail: `REST route '${m[1]}${m[2]}' has no permission_callback — the endpoint defaults to public (auth bypass).` });
  }

  // Raw form / request handlers — a handler registered on a request hook that
  // reads request data directly (not via AJAX / admin-post / REST). These are
  // the direct `add_action('init'|'admin_init'|'wp_loaded'|'template_redirect', ...)`
  // form processors that bypass the normal AJAX/admin-post CSRF + auth flow.
  const formRe = /add_action\s*\(\s*['"](init|admin_init|wp_loaded|template_redirect|parse_request|wp)['"]\s*,\s*(.+?)\s*\)/g;
  while ((m = formRe.exec(code)) !== null) {
    const hook = m[1];
    const handler = handlerName(m[2]);
    if (!handler) continue;
    const body = functionBody(code, handler);
    if (!body) continue;
    // Only a request handler if it actually reads request input.
    if (!/\$_(GET|POST|REQUEST|COOKIE|SERVER)\b|php:\/\/input|filter_input|file_get_contents\(['"]php:\/\/input/.test(body)) continue;
    const hasCap = AUTH_RE.test(body) || INDIRECT_AUTH.test(body);
    const hasNonce = NONCE_RE.test(body);
    const dangerous = DANGEROUS_OP_RE.test(body);
    const line = lineNoOf(code, m.index);
    if (!hasNonce && dangerous) {
      out.push({ file, line, type: "missing_nonce", category: "Missing nonce verification (direct request handler)", severity: "medium", evidence: `add_action('${hook}', ...)`, detail: `Request handler '${handler}()' (on '${hook}') performs a state-changing operation without nonce verification — CSRF.` });
    }
    if (!hasCap && dangerous) {
      out.push({ file, line, type: "missing_authz", category: "Missing capability check (direct request handler)", severity: "high", evidence: `add_action('${hook}', ...)`, detail: `Request handler '${handler}()' (on '${hook}') performs a privileged/state-changing operation with no capability check — auth bypass / privilege escalation.` });
    }
  }
}

interface RouteDetector {
  framework: string;
  entry: RegExp;
  auth: RegExp;
  window: number;
}

// Non-WP frameworks: route/decorator/annotation entry points + a surrounding
// window in which the authorization enforcement must appear.
const ROUTE_DETECTORS: RouteDetector[] = [
  { framework: "laravel", entry: /Route::(?:get|post|put|patch|delete|any|match|resource)\s*\(\s*['"][^'"]+['"]/g, auth: /->middleware\s*\(\s*['"]auth|middleware\s*\(\s*\[[^\]]*['"]auth|->can\s*\(|\$this->authorize|Gate::|authorize\s*\(|@can\b/, window: 2 },
  { framework: "django", entry: /@api_view\s*\(|def\s+\w+\s*\(\s*request\s*[,)]/g, auth: /login_required|permission_required|user_passes_test|LoginRequiredMixin|PermissionRequiredMixin|permission_classes|IsAuthenticated|has_permission/, window: 3 },
  { framework: "flask", entry: /@(?:app|bp|blueprint)\.(?:route|get|post|put|delete|patch|before_request)\s*\(/g, auth: /login_required|require_auth|auth_required|jwt_required|token_required|current_user|is_authenticated|before_request|verify_token|permission_required/, window: 3 },
  { framework: "express", entry: /(?<!@)(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"][^'"]+['"]/g, auth: /requireAuth|require_auth|requireAdmin|requireRole|requirePermission|isAdmin|checkRole|getApiKeyFromRequest|verifyApiKey|checkApiKey|verifyInternalToken|authenticate|passport\.authenticate|req\.user|isAuthenticated|ensureAuthenticated|requireLogin|\.authorize|authMiddleware|verifyToken|verify_token|jwt\.verify|\bbearer\b|apiAuth/, window: 3 },
  { framework: "spring", entry: /@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(/g, auth: /@PreAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority|isAuthenticated|SecurityContextHolder/, window: 2 },
  { framework: "symfony", entry: /#\[(?:Route|Get|Post|Put|Delete|Patch)\b|@Route\s*\(/g, auth: /is_granted|denyAccessUnlessGranted|->isGranted\s*\(|IsGranted|Voter/, window: 2 },
  { framework: "aspnet", entry: /\[Http(?:Get|Post|Put|Delete|Patch)\b/g, auth: /\[Authorize|User\.Identity|IsInRole|AuthorizeAsync|\[AllowAnonymous|IAuthorizationService/, window: 2 },
  { framework: "rails", entry: /class\s+\w+\s*<\s*ApplicationController/g, auth: /before_action\s+:authenticate|before_action\s+:authorize|authenticate_user!|authorize\s+|current_user|authenticate/, window: 6 },
];

// Routes that are public BY DESIGN — no auth is correct, so they must not be
// flagged. Covers register/login/signup/signin/logout/health/status/static/
// docs/config/echo/robots/sitemap/asset/GraphQL-discovery routes.
const PUBLIC_ROUTE_RE = /['"`]\/?(?:(?:api|v1|v2|o|auth|adminapi|system|internal)\/)?(?:register|login|logout|signup|signin|forgot-password|reset-password|health|healthz|ready|status|version|ping|static|public|assets|css|js|img|favicon|echo|config|docs|openapi|swagger|robots|sitemap|graphql|graphiql|query|upload|callback|webhook|home|index|root|jwks|well-known|openid-configuration|traces|logs|metrics)[/'"?]|['"`]\/?['"`](?!["'`])/i;
// A public path SEGMENT anywhere in the route — e.g. `/api/system/version`,
// `/.well-known/jwks.json`, `/v1/metrics` (multi-segment paths the first
// alternative misses).
const PUBLIC_SEGMENT_RE = /['"`][^'"`]*\/(?:version|health|healthz|ready|status|ping|jwks|openid-configuration|well-known|metrics|traces|logs|favicon|robots|sitemap)(?:[.\/'"?]|$)/i;

function detectRouteAuthz(code: string, file: string, out: ComplexFinding[]): void {
  const ls = code.split("\n");
  for (const d of ROUTE_DETECTORS) {
    d.entry.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = d.entry.exec(code)) !== null) {
      const ln = lineNoOf(code, m.index);
      const window = ls.slice(Math.max(0, ln - d.window), Math.min(ls.length, ln + d.window + 1)).join("\n");
      // Skip public-by-design routes (register/login/health/static/...) — these
      // legitimately carry no auth, and flagging them is a false positive.
      if (PUBLIC_ROUTE_RE.test(m[0] + " " + window) || PUBLIC_SEGMENT_RE.test(m[0] + " " + window)) continue;
      if (d.auth.test(window)) continue; // authorization is enforced nearby
      out.push({
        file, line: ln, type: "missing_authz",
        category: `${d.framework}: endpoint without authorization`,
        severity: "high",
        evidence: (ls[ln - 1] ?? "").trim(),
        detail: `${d.framework} endpoint has no authorization enforcement in the surrounding ${d.window}-line window — auth bypass / privilege escalation.`,
      });
    }
  }
}

/** Detect missing authorization / nonce across ALL supported frameworks. */
export function detectMissingAuthz(code: string, file: string): ComplexFinding[] {
  const out: ComplexFinding[] = [];
  detectWpAuthz(code, file, out);
  detectRouteAuthz(code, file, out);
  const seen = new Set<string>();
  return out.filter((f) => {
    const key = `${f.type}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
