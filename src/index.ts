#!/usr/bin/env node
/** BlitzStrike CLI entry.
 *
 *   blitzstrike serve --mcp     start the MCP server over stdio (default transport)
 *   blitzstrike doctor          environment health check (runtime + tools + creds)
 *   blitzstrike install         write MCP client config to detected clients
 *   blitzstrike install --dry-run   print the config without writing
 *   blitzstrike version         print version
 */
import { serve } from "./server.js";
import { runDoctor, runInstall } from "./cli.js";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
function readVersion(): string {
  try {
    const p = join(ROOT, "package.json");
    if (existsSync(p)) return (JSON.parse(readFileSync(p, "utf8")) as { version?: string }).version ?? "1.0.0";
  } catch { /* ignore */ }
  return "1.0.0";
}
const VERSION = readVersion();

function usage(): string {
  return `BlitzStrike ${VERSION} — MCP security-audit toolbelt

Usage:
  blitzstrike serve --mcp       Start the MCP server over stdio (default transport)
  blitzstrike doctor            Environment health check (runtime + tools + creds)
  blitzstrike install           Write MCP client config to detected clients
  blitzstrike install --dry-run Print the config without writing
  blitzstrike sync-data        Fetch heavy datasets (payloads + templates) on-demand
  blitzstrike update           Check for a newer version + refresh the data cache
  blitzstrike version          Print version
  blitzstrike --help           This help`;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return;
  }
  if (args[0] === "version" || args[0] === "--version" || args[0] === "-v") {
    console.log(`blitzstrike ${VERSION}`);
    return;
  }
  if (args[0] === "doctor") {
    runDoctor();
    return;
  }
  if (args[0] === "install") {
    runInstall(args.includes("--dry-run"));
    return;
  }
  if (args[0] === "sync-data") {
    const { syncData } = await import("./sync.js");
    const r = syncData();
    console.log("Blitz Strike data sync");
    console.log(`  data root: ${r.data_root}`);
    console.log(`  payloads:  ${r.payloads.files} files ${r.payloads.synced ? "(synced)" : "(already present)"}`);
    console.log(`  templates: ${r.templates.files} files ${r.templates.synced ? "(synced)" : "(already present)"}`);
    return;
  }
  if (args[0] === "update") {
    const { runUpdate } = await import("./update.js");
    const r = await runUpdate(VERSION);
    console.log("Blitz Strike self-update");
    console.log(`  current: ${r.current}`);
    console.log(`  latest:  ${r.latest ?? "unknown (registry unreachable)"}`);
    if (r.outdated) {
      console.log(`  status:  OUTDATED — update with: ${r.update_command}`);
    } else if (r.latest === null) {
      console.log(`  status:  could not reach npm registry`);
    } else {
      console.log(`  status:  up to date`);
    }
    console.log(`  data:    payloads ${r.data_sync.payloads.files} files, templates ${r.data_sync.templates.files} files ${r.data_sync.payloads.synced ? "(refreshed)" : ""}`);
    return;
  }
  if (args[0] === "serve") {
    await serve();
    return;
  }
  console.log(usage());
}

await main();
