/** Minimal MCP stdio client + chrome-devtools-mcp driver.
 *
 * Blitz acts as an MCP CLIENT: it spawns chrome-devtools-mcp, performs the
 * initialize handshake, then drives its tools (navigate_page, list_network_requests,
 * list_console_messages, evaluate_script) against a target. This turns the
 * "browser_devtools" chain hint into a REAL browser session instead of a
 * connection string the LLM has to wire up manually.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface McpResult {
  ok: boolean;
  server?: string;
  error?: string;
  [key: string]: unknown;
}

interface Pending {
  resolve: (res: { id?: number; result?: unknown; error?: unknown }) => void;
}

/** A line-delimited JSON-RPC MCP stdio client. */
function mcpClient(command: string, args: string[]) {
  const proc = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
  let id = 0;
  const pending = new Map<number, Pending>();
  let buffer = "";

  proc.stdout.on("data", (chunk: Buffer) => {
    buffer += chunk.toString();
    let idx: number;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const d = JSON.parse(line);
        if (d.id != null && pending.has(d.id)) {
          const p = pending.get(d.id)!;
          pending.delete(d.id);
          p.resolve(d);
        }
      } catch {
        /* ignore non-JSON lines (logs) */
      }
    }
  });

  function request(method: string, params: unknown): Promise<{ id?: number; result?: unknown; error?: unknown }> {
    const reqId = ++id;
    return new Promise((resolve) => {
      pending.set(reqId, { resolve });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: reqId, method, params }) + "\n");
    });
  }

  return {
    proc,
    async initialize(): Promise<unknown> {
      const r = await request("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "blitzstrike", version: "2" },
      });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      return r.result;
    },
    async call(name: string, args: Record<string, unknown>): Promise<unknown> {
      const r = await request("tools/call", { name, arguments: args });
      return r.result ?? r.error;
    },
    close() {
      try {
        proc.kill();
      } catch {
        /* already gone */
      }
    },
  };
}

/** Extract the text content from an MCP tools/call result. */
function mcpText(result: unknown): string {
  if (result == null) return "";
  const r = result as { content?: Array<{ type?: string; text?: string }>; text?: string };
  if (typeof r.text === "string") return r.text;
  if (Array.isArray(r.content)) return r.content.map((c) => (c && typeof c.text === "string" ? c.text : "")).join("\n");
  return JSON.stringify(result);
}

/** Discover a usable Chromium binary: a system Chrome first, then playwright's cache. */
function findChromium(): string | null {
  const candidates = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"];
  for (const c of candidates) {
    for (const dir of ["/usr/bin", "/usr/local/bin", "/opt/google/chrome"]) {
      const p = join(dir, c);
      if (existsSync(p)) return p;
    }
  }
  const pw = join(homedir(), ".cache", "ms-playwright");
  if (existsSync(pw)) {
    for (const d of readdirSync(pw)) {
      if (!d.startsWith("chromium")) continue;
      const full = join(pw, d, "chrome-linux64", "chrome");
      if (existsSync(full)) return full;
    }
  }
  return null;
}

function chromeDevtoolsCommand(): { command: string; args: string[] } | null {
  for (const c of ["/usr/bin/chrome-devtools-mcp", "/usr/local/bin/chrome-devtools-mcp"]) {
    if (existsSync(c)) return { command: c, args: [] };
  }
  // Auto-install fallback: npx fetches chrome-devtools-mcp on first use
  // (zero global install). Cached by npx on subsequent runs.
  const npx = spawnSync("npx", ["--version"], { timeout: 8000 });
  if (npx.error === undefined) return { command: "npx", args: ["-y", "chrome-devtools-mcp@latest"] };
  return null;
}

/** Parse the pageId from list_pages markdown ("N: url [selected]"). */
export function parsePageId(text: string): number {
  const m = text.match(/^(\d+):/m);
  return m ? parseInt(m[1], 10) : 1;
}

/** Spawn chrome-devtools-mcp, navigate to a target, and capture network traffic +
 * console messages + a JS evaluation. This is the auto-verification of the
 * "browser_devtools" chain hint — a real browser session, not a connect string. */
export async function driveChromeDevtools(target: string, timeoutMs = 25000): Promise<McpResult> {
  const bin = chromeDevtoolsCommand();
  if (!bin) {
    return { ok: false, error: "chrome-devtools-mcp not available (no global binary and no npx) — install Node/npm first" };
  }
  const chrome = findChromium();
  const args = [...bin.args, "--headless", "--isolated", "--chromeArg=--no-sandbox", "--chromeArg=--disable-gpu"];
  if (chrome) args.push(`--executablePath=${chrome}`);

  const client = mcpClient(bin.command, args);
  const timer = setTimeout(() => client.close(), timeoutMs);

  try {
    const init = (await client.initialize()) as { serverInfo?: { name?: string; version?: string } };
    const server = `${init?.serverInfo?.name ?? "chrome_devtools"} v${init?.serverInfo?.version ?? "?"}`;

    // list_pages -> pageId
    const pagesTxt = mcpText(await client.call("list_pages", {}));
    const pageId = parsePageId(pagesTxt);

    // navigate
    const navTxt = mcpText(await client.call("navigate_page", { pageId, url: target }));
    const navigated = /successfully navigated/i.test(navTxt) || !/error/i.test(navTxt);

    // give the page a moment to settle + issue requests
    await new Promise((r) => setTimeout(r, 1800));

    const networkTxt = mcpText(await client.call("list_network_requests", { pageId }));
    const consoleTxt = mcpText(await client.call("list_console_messages", { pageId }));
    const evalTxt = mcpText(
      await client.call("evaluate_script", {
        pageId,
        function: "() => ({ title: document.title, url: location.href, bodyText: (document.body && document.body.innerText || '').slice(0, 200) })",
      }),
    );

    return {
      ok: true,
      server,
      navigated,
      page: navTxt,
      network_requests: networkTxt.slice(0, 3000),
      console_messages: consoleTxt.slice(0, 3000),
      evaluate: evalTxt.slice(0, 2000),
    };
  } catch (e) {
    return { ok: false, error: String(e) };
  } finally {
    clearTimeout(timer);
    client.close();
  }
}
