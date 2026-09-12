/** Browser Validation (Phase 6) — Playwright-based, use only when necessary.
 *
 * Static analysis produces *hypotheses*; this module *validates* them by driving
 * a real headless Chromium. It is deliberately NOT a scanner — it is gated
 * (requires an explicit hypothesis + target) and requires `playwright-core`
 * (an optional peer dependency) + a matching Chromium.
 *
 * Checks:
 *   - dom_xss       : inject a marker payload and detect execution (window marker)
 *   - open_redirect : navigate and detect an unexpected client-side redirect
 *   - auth_bypass   : detect whether a protected endpoint enforces auth (401/403/login)
 *   - csrf          : detect state-changing forms missing a CSRF token
 *
 * Every check returns structured evidence (verdict + final_url + dom/console/
 * network signals) that can be attached to a finding.
 */
/// <reference lib="dom" />
import { redactSecrets } from "./evidence.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type BrowserCheck = "dom_xss" | "open_redirect" | "auth_bypass" | "csrf";

export interface BrowserEvidence {
  check: BrowserCheck;
  target: string;
  verdict: "confirmed" | "not_confirmed" | "error" | "unavailable";
  detail: string;
  evidence: {
    final_url?: string;
    dom_marker?: boolean;
    status?: number;
    csrf_token_present?: boolean;
    forms_count?: number;
    console_errors: string[];
    page_errors: string[];
  };
}

type ChromiumModule = typeof import("playwright-core");

let chromiumCache: ChromiumModule | null = null;

async function ensureChromium(): Promise<ChromiumModule | null> {
  if (chromiumCache) return chromiumCache;
  try {
    chromiumCache = await import("playwright-core");
    return chromiumCache;
  } catch {
    return null;
  }
}

function unavailable(check: BrowserCheck, target: string, reason: string): BrowserEvidence {
  return {
    check,
    target: redactSecrets(target),
    verdict: "unavailable",
    detail: reason,
    evidence: { console_errors: [], page_errors: [] },
  };
}

function errorEvidence(check: BrowserCheck, target: string, e: unknown): BrowserEvidence {
  return {
    check,
    target: redactSecrets(target),
    verdict: "error",
    detail: e instanceof Error ? e.message : String(e),
    evidence: { console_errors: [], page_errors: [] },
  };
}

/** Launch headless Chromium; return null on failure (e.g. no binary installed),
 * so a missing browser degrades to "unavailable" instead of throwing. */
async function launchHeadless(chr: ChromiumModule): Promise<import("playwright-core").Browser | null> {
  try {
    return await chr.chromium.launch({ headless: true });
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/** DOM XSS: navigate with a marker payload and detect execution. */
export async function validateDomXss(target: string, payload = "<img src=x onerror=\"window.__blitz_xss__=true\">"): Promise<BrowserEvidence> {
  const chr = await ensureChromium();
  if (!chr) return unavailable("dom_xss", target, "playwright-core not installed (optional peer dependency)");
  const browser = await launchHeadless(chr);
  if (!browser) return unavailable("dom_xss", target, "Chromium launch failed (no browser binary installed)");
  try {
    const page = await browser.newPage();
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
    page.on("pageerror", (e) => pageErrors.push(String(e)));

    const url = target.includes("{{payload}}")
      ? target.replace("{{payload}}", encodeURIComponent(payload))
      : target;
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(600);
    const marker = await page.evaluate(() => (window as unknown as { __blitz_xss__?: boolean }).__blitz_xss__ === true);

    return {
      check: "dom_xss",
      target: redactSecrets(target),
      verdict: marker ? "confirmed" : "not_confirmed",
      detail: marker ? "payload executed (marker set)" : "payload did not execute (no marker)",
      evidence: { final_url: page.url(), dom_marker: marker, console_errors: consoleErrors, page_errors: pageErrors },
    };
  } catch (e) {
    return errorEvidence("dom_xss", target, e);
  } finally {
    await browser.close();
  }
}

/** Open redirect: navigate and detect whether the browser lands on the attacker URL. */
export async function validateOpenRedirect(target: string, payload: string): Promise<BrowserEvidence> {
  const chr = await ensureChromium();
  if (!chr) return unavailable("open_redirect", target, "playwright-core not installed (optional peer dependency)");
  const browser = await launchHeadless(chr);
  if (!browser) return unavailable("open_redirect", target, "Chromium launch failed (no browser binary installed)");
  try {
    const page = await browser.newPage();
    const url = target.includes("{{payload}}")
      ? target.replace("{{payload}}", encodeURIComponent(payload))
      : target;
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(400);
    const finalUrl = page.url();
    const redirected = finalUrl !== url && finalUrl.includes(payload);
    return {
      check: "open_redirect",
      target: redactSecrets(target),
      verdict: redirected ? "confirmed" : "not_confirmed",
      detail: redirected ? `browser redirected to ${finalUrl}` : `no redirect to attacker URL (final: ${finalUrl})`,
      evidence: { final_url: finalUrl, console_errors: [], page_errors: [] },
    };
  } catch (e) {
    return errorEvidence("open_redirect", target, e);
  } finally {
    await browser.close();
  }
}

/** Auth bypass: detect whether a protected endpoint enforces authentication. */
export async function validateAuthBypass(target: string): Promise<BrowserEvidence> {
  const chr = await ensureChromium();
  if (!chr) return unavailable("auth_bypass", target, "playwright-core not installed (optional peer dependency)");
  const browser = await launchHeadless(chr);
  if (!browser) return unavailable("auth_bypass", target, "Chromium launch failed (no browser binary installed)");
  try {
    const page = await browser.newPage();
    const resp = await page.goto(target, { waitUntil: "domcontentloaded", timeout: 15000 });
    const status = resp?.status() ?? 0;
    const finalUrl = page.url();
    const enforced = status === 401 || status === 403 || /login|signin|auth/.test(finalUrl);
    return {
      check: "auth_bypass",
      target: redactSecrets(target),
      verdict: enforced ? "not_confirmed" : "confirmed",
      detail: enforced
        ? `auth enforced (status ${status}, final ${finalUrl})`
        : `no auth enforcement observed (status ${status}, final ${finalUrl})`,
      evidence: { final_url: finalUrl, status, console_errors: [], page_errors: [] },
    };
  } catch (e) {
    return errorEvidence("auth_bypass", target, e);
  } finally {
    await browser.close();
  }
}

/** CSRF: detect state-changing forms missing a CSRF token. */
export async function validateCsrf(target: string): Promise<BrowserEvidence> {
  const chr = await ensureChromium();
  if (!chr) return unavailable("csrf", target, "playwright-core not installed (optional peer dependency)");
  const browser = await launchHeadless(chr);
  if (!browser) return unavailable("csrf", target, "Chromium launch failed (no browser binary installed)");
  try {
    const page = await browser.newPage();
    await page.goto(target, { waitUntil: "domcontentloaded", timeout: 15000 });
    const result = await page.evaluate(() => {
      const forms = Array.from(document.querySelectorAll("form"));
      const stateChanging = forms.filter((f) => /post/i.test(f.method) || f.method === "");
      if (stateChanging.length === 0) return { token: true, count: 0 };
      for (const f of stateChanging) {
        const token = f.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="nonce"]');
        if (!token) return { token: false, count: stateChanging.length };
      }
      return { token: true, count: stateChanging.length };
    });
    return {
      check: "csrf",
      target: redactSecrets(target),
      verdict: result.token ? "not_confirmed" : "confirmed",
      detail: result.token
        ? `CSRF token present (${result.count} form(s))`
        : `state-changing form missing CSRF token (${result.count} form(s))`,
      evidence: { csrf_token_present: result.token, forms_count: result.count, console_errors: [], page_errors: [] },
    };
  } catch (e) {
    return errorEvidence("csrf", target, e);
  } finally {
    await browser.close();
  }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/** Run a browser validation check (dispatcher used by the MCP tool). */
export async function browserValidate(check: BrowserCheck, target: string, payload?: string): Promise<BrowserEvidence> {
  switch (check) {
    case "dom_xss": return validateDomXss(target, payload);
    case "open_redirect": return validateOpenRedirect(target, payload ?? "https://attacker.example/");
    case "auth_bypass": return validateAuthBypass(target);
    case "csrf": return validateCsrf(target);
  }
}
