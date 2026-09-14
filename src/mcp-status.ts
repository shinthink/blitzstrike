/** MCP server availability checks — verify that external MCP integrations
 * (chrome-devtools-mcp, burp-suite-mcp) are actually present/connected, so the
 * pipeline knows BEFORE it needs them instead of failing at test time.
 */

import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { driveBurpMCP } from "./burp-mcp.js";

export interface McpServerStatus {
  name: string;
  available: boolean;
  kind: "stdio" | "sse";
  detail: string;
  fix?: string;
}

/** Lightweight availability probe for every external MCP integration. */
export async function checkMcpServers(): Promise<McpServerStatus[]> {
  const out: McpServerStatus[] = [];

  // chrome-devtools-mcp (stdio) — global binary OR npx zero-install fallback.
  const bin = ["/usr/bin/chrome-devtools-mcp", "/usr/local/bin/chrome-devtools-mcp"].find((p) => existsSync(p));
  const npxOk = spawnSync("npx", ["--version"], { timeout: 8000 }).error === undefined;
  const devtoolsOk = Boolean(bin) || npxOk;
  out.push({
    name: "chrome-devtools-mcp",
    available: devtoolsOk,
    kind: "stdio",
    detail: bin ? `installed at ${bin}` : npxOk ? "not installed — will auto-install via npx on first use" : "not installed (no npx either)",
    fix: devtoolsOk ? undefined : "install Node/npm, then `npm i -g chrome-devtools-mcp`",
  });

  // burp-suite-mcp (SSE) — alive only when Burp is running + extension loaded.
  const burp = await driveBurpMCP("http://127.0.0.1:9876", 4000);
  out.push({
    name: "burp-suite-mcp",
    available: burp.alive,
    kind: "sse",
    detail: burp.alive
      ? `alive at ${burp.base_url}${burp.endpoint ? ` (endpoint ${burp.endpoint})` : ""}`
      : (burp.error ?? "not reachable"),
    fix: burp.alive ? undefined : "build PortSwigger/mcp-server (`./gradlew embedProxyJar`) + load the JAR in Burp → Extensions, then enable the MCP extension",
  });

  return out;
}
