// Browser validation hermetic test (Phase 6).
//
// Spins up a local vulnerable server and verifies that each Playwright check
// (dom_xss / open_redirect / auth_bypass / csrf) both CONFIRMS the vulnerable
// case and does NOT confirm the hardened case.
//
// Run: bun run test:browser   (requires playwright-core + chromium)
import { createServer } from "node:http";
import { validateDomXss, validateOpenRedirect, validateAuthBypass, validateCsrf } from "../src/browser.ts";
import { browserOpen, detectAuthForm, browserType, browserEvaluate, browserClose, browserDiagnostics } from "../src/browser-agent.ts";

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) {
    pass += 1;
    console.log(`PASS  ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL  ${name}  ${detail}`);
  }
}

// local server with vulnerable + hardened endpoints
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/xss") {
    res.setHeader("Content-Type", "text/html");
    res.end(`<html><body><div>${url.searchParams.get("q") ?? ""}</div></body></html>`);
  } else if (url.pathname === "/xss-safe") {
    // escapes the input (no XSS)
    const q = (url.searchParams.get("q") ?? "").replace(/[<>&"]/g, "");
    res.setHeader("Content-Type", "text/html");
    res.end(`<html><body><div>${q}</div></body></html>`);
  } else if (url.pathname === "/redirect") {
    const u = url.searchParams.get("url") ?? "/";
    res.writeHead(302, { Location: u });
    res.end();
  } else if (url.pathname === "/redirect-safe") {
    // only allows same-origin redirects
    const u = url.searchParams.get("url") ?? "/";
    if (u.startsWith("/")) {
      res.writeHead(302, { Location: u });
    } else {
      res.writeHead(200, { "Content-Type": "text/plain" });
    }
    res.end();
  } else if (url.pathname === "/admin") {
    res.setHeader("Content-Type", "text/html");
    res.end("<html><body>ADMIN SECRET DATA</body></html>");
  } else if (url.pathname === "/protected") {
    res.writeHead(401);
    res.end("unauthorized");
  } else if (url.pathname === "/form") {
    res.setHeader("Content-Type", "text/html");
    res.end('<html><body><form method="POST" action="/transfer"><input name="to"><input name="amount"></form></body></html>');
  } else if (url.pathname === "/form-safe") {
    res.setHeader("Content-Type", "text/html");
    res.end('<html><body><form method="POST" action="/transfer"><input name="_token" value="csrf123"><input name="to"></form></body></html>');
  } else if (url.pathname === "/login") {
    res.setHeader("Content-Type", "text/html");
    res.end('<html><body><form method="POST" action="/login"><input type="text" name="username"><input type="password" name="password"></form></body></html>');
  } else {
    res.writeHead(404);
    res.end();
  }
});

await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const addr = server.address();
const port = typeof addr === "object" && addr ? addr.port : 0;
const base = `http://127.0.0.1:${port}`;

// dom_xss
const xss = await validateDomXss(`${base}/xss?q={{payload}}`);
check("dom_xss: vulnerable confirmed", xss.verdict === "confirmed", xss.detail);
const xssSafe = await validateDomXss(`${base}/xss-safe?q={{payload}}`);
check("dom_xss: escaped not confirmed", xssSafe.verdict === "not_confirmed", xssSafe.detail);

// open_redirect
const redir = await validateOpenRedirect(`${base}/redirect?url={{payload}}`, `${base}/admin`);
check("open_redirect: vulnerable confirmed", redir.verdict === "confirmed", redir.detail);
const redirSafe = await validateOpenRedirect(`${base}/redirect-safe?url={{payload}}`, `${base}/admin`);
check("open_redirect: whitelisted not confirmed", redirSafe.verdict === "not_confirmed", redirSafe.detail);

// auth_bypass
const auth = await validateAuthBypass(`${base}/admin`);
check("auth_bypass: unauthenticated admin confirmed", auth.verdict === "confirmed", auth.detail);
const authSafe = await validateAuthBypass(`${base}/protected`);
check("auth_bypass: 401 protected not confirmed", authSafe.verdict === "not_confirmed", authSafe.detail);

// csrf
const csrf = await validateCsrf(`${base}/form`);
check("csrf: tokenless form confirmed", csrf.verdict === "confirmed", csrf.detail);
const csrfSafe = await validateCsrf(`${base}/form-safe`);
check("csrf: tokenized form not confirmed", csrfSafe.verdict === "not_confirmed", csrfSafe.detail);

// session-based browser agent (Phase 12)
const opened = await browserOpen(`${base}/login`);
check("browser_agent: open succeeds", opened.ok && !opened.unavailable, opened.detail);
const authForm = await detectAuthForm();
const af = (authForm.value ?? {}) as { found?: boolean; has_user?: boolean; has_pass?: boolean };
check("browser_agent: login form detected", af.found === true && af.has_user === true && af.has_pass === true, JSON.stringify(authForm.value));
const typed = await browserType('input[name="username"]', "admin");
check("browser_agent: type succeeds", typed.ok, typed.detail);
const title = await browserEvaluate("document.title || 'no-title'");
check("browser_agent: evaluate works", title.ok && title.value !== undefined, String(title.value));
const diag = browserDiagnostics();
check("browser_agent: diagnostics shape", Array.isArray(diag.console_errors) && Array.isArray(diag.page_errors), "diag");
await browserClose();

server.close();
console.log(`\n${pass}/${pass + fail} browser checks passed`);
process.exit(fail === 0 ? 0 : 1);
