/** Burp Suite MCP auto-verification over SSE.
 *
 * The Burp MCP extension hosts an SSE server (default http://127.0.0.1:9876).
 * This module detects whether it is alive and, if so, performs the MCP SSE
 * handshake + tools/list so the pipeline knows Burp is actually connected —
 * instead of just returning a connect string that may error at test time.
 */
export interface BurpMcpResult {
  ok: boolean;
  alive: boolean;
  base_url: string;
  endpoint?: string | null;
  server?: string;
  tools?: string;
  error?: string;
}

const DEFAULT_BURP_URL = "http://127.0.0.1:9876";

/** Minimal fetch with a timeout. */
async function fetchTimeout(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

/** Extract the JSON-RPC result from an SSE message stream (event: message). */
export function sseMessage(text: string): string | null {
  // SSE: "event: message\ndata: {...}\n\n"
  const m = text.match(/event:\s*message[\s\S]*?data:\s*([^\n]+)/);
  return m ? m[1].trim() : null;
}

/** Detect whether the Burp MCP SSE server is reachable + perform the MCP handshake. */
export async function driveBurpMCP(baseUrl: string = DEFAULT_BURP_URL, timeoutMs = 10000): Promise<BurpMcpResult> {
  const base = baseUrl.replace(/\/+$/, "");
  // 1. Open the SSE stream (this is the "is Burp running" signal).
  let sseRes: Response;
  try {
    sseRes = await fetchTimeout(`${base}/sse`, { headers: { Accept: "text/event-stream" } }, timeoutMs);
  } catch (e) {
    return { ok: false, alive: false, base_url: base, error: `Burp MCP not reachable at ${base}/sse (${String(e)}) — start Burp + load the MCP extension` };
  }

  if (!sseRes.ok) {
    return {
      ok: false,
      alive: false,
      base_url: base,
      error: `Burp MCP SSE endpoint returned HTTP ${sseRes.status} — is the extension enabled in Burp → MCP?`,
    };
  }

  // 2. Read the SSE stream for the endpoint event + any messages.
  let endpoint: string | null = null;
  let serverInfo = "";
  let toolsRaw = "";
  try {
    const reader = sseRes.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      if (!endpoint) {
        const em = buf.match(/event:\s*endpoint[\s\S]*?data:\s*([^\n]+)/);
        if (em) endpoint = em[1].trim();
      }
      if (endpoint) break;
    }
    if (endpoint) {
      // 3. POST initialize + tools/list to the message endpoint.
      const postUrl = new URL(endpoint, base).toString();
      const initRes = await fetchTimeout(postUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "blitzstrike", version: "2" } },
        }),
      }, timeoutMs);
      const initText = await initRes.text();
      const initMsg = sseMessage(initText) ?? (initText.includes("result") ? initText : "");
      serverInfo = initMsg.slice(0, 600);

      const toolsRes = await fetchTimeout(postUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
      }, timeoutMs);
      const toolsText = await toolsRes.text();
      toolsRaw = (sseMessage(toolsText) ?? toolsText).slice(0, 3000);
    }
  } catch (e) {
    return { ok: true, alive: true, base_url: base, endpoint, error: `SSE stream opened but handshake failed: ${String(e)}` };
  }

  if (!endpoint) {
    return {
      ok: true,
      alive: true,
      base_url: base,
      error: "SSE stream open but no endpoint event received — Burp MCP extension may not be fully enabled",
    };
  }

  return { ok: true, alive: true, base_url: base, endpoint, server: serverInfo, tools: toolsRaw };
}
