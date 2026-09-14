/** Screenshot capture — visual proof for reports (vision validation).
 *
 *  Captures a headless-browser screenshot of a page and saves it to a file so the
 *  agent can inspect it with a vision model (a rendered XSS alert, an IDOR data
 *  leak, a working login) as additional evidence on top of the marker + control.
 */
import { browserOpen, browserScreenshot, browserClose } from "./browser-agent.js";
import { join } from "node:path";
import { homedir } from "node:os";

export interface ScreenshotResult {
  ok: boolean;
  url: string;
  path?: string;
  detail: string;
}

export async function screenshot(url: string, path?: string): Promise<ScreenshotResult> {
  const out = path ?? join(homedir(), ".blitzstrike", `shot-${Date.now()}.png`);
  const opened = await browserOpen(url);
  if (!opened.ok) {
    return { ok: false, url, detail: opened.unavailable ? `browser unavailable (${opened.detail}) — install playwright-core + a chromium, or use drive_devtools` : `open failed: ${opened.detail}` };
  }
  const shot = await browserScreenshot(out);
  await browserClose();
  if (!shot.ok) {
    return { ok: false, url, detail: `screenshot failed: ${shot.detail}` };
  }
  return { ok: true, url, path: out, detail: `saved ${out} — inspect with a vision model (vision_analyze) to confirm the rendered state` };
}
