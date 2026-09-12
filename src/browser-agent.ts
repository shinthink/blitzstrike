/** Browser Automation Agent (Phase 12 / §16).
 *
 * A session-based browser agent that drives a real headless Chromium. Unlike the
 * per-check `browser.ts` validators, this maintains ONE persistent page so it can
 * run multi-step flows (login → MFA → session) and interact with the DOM.
 *
 * Operations: open, navigate, click, type, evaluate, screenshot, back, forward,
 * get_cookie, set_cookie. Graceful degradation: if `playwright-core` (optional
 * peer) is absent, every op reports `unavailable` instead of throwing.
 */
import { redactSecrets } from "./evidence.js";

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

export type BrowserOp =
  | "open"
  | "navigate"
  | "click"
  | "type"
  | "evaluate"
  | "screenshot"
  | "back"
  | "forward"
  | "get_cookie"
  | "set_cookie";

export interface BrowserResult {
  op: BrowserOp;
  ok: boolean;
  unavailable: boolean;
  detail: string;
  value?: unknown;
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

type AnyPage = {
  goto(url: string, opts?: Record<string, unknown>): Promise<unknown>;
  url(): string;
  click(selector: string): Promise<void>;
  fill(selector: string, text: string): Promise<void>;
  evaluate<T>(js: string | ((...args: unknown[]) => unknown), arg?: unknown): Promise<T>;
  screenshot(opts?: Record<string, unknown>): Promise<Buffer>;
  goBack(): Promise<unknown>;
  goForward(): Promise<unknown>;
  context(): { cookies(): Promise<Array<{ name: string; value: string }>>; addCookies(cookies: Array<Record<string, unknown>>): Promise<void> };
  on(event: string, cb: (arg: unknown) => void): void;
};

type AnyBrowser = { newPage(): Promise<AnyPage>; close(): Promise<void> };
type AnyChromium = { chromium: { launch(opts?: Record<string, unknown>): Promise<AnyBrowser> } };

let browser: AnyBrowser | null = null;
let page: AnyPage | null = null;
const consoleErrors: string[] = [];
const pageErrors: string[] = [];

async function ensureSession(): Promise<{ available: boolean; reason?: string }> {
  if (page) return { available: true };
  const chr = (await ensureChromium()) as unknown as AnyChromium | null;
  if (!chr) return { available: false, reason: "playwright-core not installed (optional peer dependency)" };
  try {
    browser = await chr.chromium.launch({ headless: true });
    page = await browser.newPage();
    page.on("console", (m) => {
      const msg = m as { type(): string; text(): string };
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (e) => pageErrors.push(String(e)));
    return { available: true };
  } catch (e) {
    return { available: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

function unavailable(op: BrowserOp, reason: string): BrowserResult {
  return { op, ok: false, unavailable: true, detail: reason };
}

function fail(op: BrowserOp, e: unknown): BrowserResult {
  return { op, ok: false, unavailable: false, detail: e instanceof Error ? e.message : String(e) };
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

export async function browserOpen(url: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("open", s.reason ?? "unavailable");
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
    return { op: "open", ok: true, unavailable: false, detail: `opened ${redactSecrets(page.url())}` };
  } catch (e) {
    return fail("open", e);
  }
}

export async function browserNavigate(url: string): Promise<BrowserResult> {
  return browserOpen(url); // same primitive, kept for the §16 surface
}

export async function browserClick(selector: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("click", s.reason ?? "unavailable");
  try {
    await page.click(selector);
    return { op: "click", ok: true, unavailable: false, detail: `clicked ${selector}` };
  } catch (e) {
    return fail("click", e);
  }
}

export async function browserType(selector: string, text: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("type", s.reason ?? "unavailable");
  try {
    await page.fill(selector, text);
    return { op: "type", ok: true, unavailable: false, detail: `typed into ${selector}` };
  } catch (e) {
    return fail("type", e);
  }
}

export async function browserEvaluate(js: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("evaluate", s.reason ?? "unavailable");
  try {
    const value = await page.evaluate<unknown>((code) => {
      const fn = new Function(`"use strict"; return (${code})`)();
      return typeof fn === "function" ? fn() : fn;
    }, js);
    return { op: "evaluate", ok: true, unavailable: false, detail: "evaluated", value };
  } catch (e) {
    return fail("evaluate", e);
  }
}

export async function browserScreenshot(path?: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("screenshot", s.reason ?? "unavailable");
  try {
    const buf = await page.screenshot(path ? { path } : {});
    return { op: "screenshot", ok: true, unavailable: false, detail: path ? `saved ${path}` : "captured (in-memory)", value: path ? undefined : buf.byteLength };
  } catch (e) {
    return fail("screenshot", e);
  }
}

export async function browserBack(): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("back", s.reason ?? "unavailable");
  try {
    await page.goBack();
    return { op: "back", ok: true, unavailable: false, detail: `back to ${redactSecrets(page.url())}` };
  } catch (e) {
    return fail("back", e);
  }
}

export async function browserForward(): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("forward", s.reason ?? "unavailable");
  try {
    await page.goForward();
    return { op: "forward", ok: true, unavailable: false, detail: `forward to ${redactSecrets(page.url())}` };
  } catch (e) {
    return fail("forward", e);
  }
}

export async function browserGetCookie(name: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("get_cookie", s.reason ?? "unavailable");
  try {
    const cookies = await page.context().cookies();
    const hit = cookies.filter((c) => c.name === name);
    return { op: "get_cookie", ok: true, unavailable: false, detail: hit.length ? "found" : "not found", value: hit };
  } catch (e) {
    return fail("get_cookie", e);
  }
}

export async function browserSetCookie(name: string, value: string): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("set_cookie", s.reason ?? "unavailable");
  try {
    const url = page.url();
    await page.context().addCookies([{ name, value, url }]);
    return { op: "set_cookie", ok: true, unavailable: false, detail: `set ${name}` };
  } catch (e) {
    return fail("set_cookie", e);
  }
}

export async function browserClose(): Promise<void> {
  if (browser) {
    await browser.close().catch(() => undefined);
    browser = null;
    page = null;
  }
}

// ---------------------------------------------------------------------------
// High-level agent flows (§16)
// ---------------------------------------------------------------------------

/** Detect a login form on the current page (for auth-flow automation). */
export async function detectAuthForm(): Promise<BrowserResult> {
  const s = await ensureSession();
  if (!s.available || !page) return unavailable("evaluate", s.reason ?? "unavailable");
  try {
    const value = await page.evaluate<Record<string, unknown>>(() => {
      const forms = Array.from(document.querySelectorAll("form"));
      const loginForm = forms.find((f) => /login|signin|auth/i.test((f as HTMLFormElement).action || "") || f.querySelector('input[type="password"]'));
      if (!loginForm) return { found: false };
      const userField = loginForm.querySelector('input[type="email"], input[type="text"], input[name*="user"], input[name*="email"], input[name*="login"]');
      const passField = loginForm.querySelector('input[type="password"]');
      return {
        found: true,
        action: (loginForm as HTMLFormElement).action || "(self)",
        has_user: Boolean(userField),
        has_pass: Boolean(passField),
        user_selector: userField ? `input[name="${(userField as HTMLInputElement).name || ""}"], input[type="${(userField as HTMLInputElement).type}"]` : null,
        pass_selector: passField ? 'input[type="password"]' : null,
      };
    });
    return { op: "evaluate", ok: true, unavailable: false, detail: value.found ? "login form detected" : "no login form", value };
  } catch (e) {
    return fail("evaluate", e);
  }
}

/** High-level agent dispatch: run a named browser op with string args. */
export async function browserAgent(op: BrowserOp, args: string[] = []): Promise<BrowserResult> {
  switch (op) {
    case "open": return browserOpen(args[0] ?? "");
    case "navigate": return browserNavigate(args[0] ?? "");
    case "click": return browserClick(args[0] ?? "");
    case "type": return browserType(args[0] ?? "", args[1] ?? "");
    case "evaluate": return browserEvaluate(args[0] ?? "");
    case "screenshot": return browserScreenshot(args[0] || undefined);
    case "back": return browserBack();
    case "forward": return browserForward();
    case "get_cookie": return browserGetCookie(args[0] ?? "");
    case "set_cookie": return browserSetCookie(args[0] ?? "", args[1] ?? "");
  }
}

/** Console + page errors captured across the session (DOM/JS issue detection). */
export function browserDiagnostics(): { console_errors: string[]; page_errors: string[] } {
  return { console_errors: [...consoleErrors], page_errors: [...pageErrors] };
}
