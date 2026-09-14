/** Out-of-band (OOB) callback listener — deterministic proof for BLIND vulns.
 *
 *  Blind SSRF / XXE / SQLi / command injection do not reflect their result in
 *  the HTTP response. The only deterministic proof is an out-of-band callback:
 *  the target fetches a canary URL/DNS name we control, and we observe the
 *  incoming interaction.
 *
 *  Two modes, in priority order:
 *   1. `interactsh`  — spawn the `interactsh-client` binary (ProjectDiscovery).
 *      It registers a unique *.oast.* domain and streams DNS/HTTP/SMTP
 *      interactions as JSONL. This is the standard for public targets (the
 *      target resolves + fetches the canary over the internet).
 *   2. `selfhost`    — a local HTTP listener (127.0.0.1:0). Zero dependency and
 *      fully deterministic, but the TARGET must be able to reach this host (a
 *      local lab / docker network). For a remote target, pair it with a tunnel
 *      (pinggy) to expose the listener publicly.
 *
 *  Session lifecycle: oob_start() -> oob_poll(id) (repeat) -> oob_stop(id).
 *  The hit is only REPORTED when an interaction with the session's unique id
 *  actually arrives — never from a guess.
 */
import { spawn, execSync, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { networkInterfaces } from "node:os";
import { existsSync } from "node:fs";

interface OobSession {
  id: string;
  mode: "interactsh" | "selfhost";
  domain?: string;
  url?: string;
  port?: number;
  proc?: ChildProcess;
  server?: Server;
  buffer: string;
  hits: Array<Record<string, unknown>>;
  startedAt: number;
}

const sessions = new Map<string, OobSession>();

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function findInteractsh(): string | null {
  try {
    const p = execSync("which interactsh-client 2>/dev/null", { encoding: "utf8", timeout: 3000 }).trim();
    if (p) return p;
  } catch {
    /* not on PATH */
  }
  const home = process.env.HOME ?? "/root";
  const candidates = [`${home}/go/bin/interactsh-client`, "/usr/local/bin/interactsh-client", "/usr/bin/interactsh-client"];
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

/** Strip ANSI color/escape codes (interactsh-client colorizes the `[INF]` banner
 *  even when piped). */
export function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\u001b\[[0-9;]*m/g, "");
}

/** Extract the registered *.oast.* domain from interactsh-client stdout. */
export function extractDomain(buffer: string): string | null {
  const m = stripAnsi(buffer).match(/\[INF\]\s+([a-z0-9]{20,}\.[a-z0-9.-]+)/i);
  return m ? m[1] : null;
}

/** Parse JSONL interaction lines from the client's accumulated stdout. */
export function parseInteractions(buffer: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const raw of stripAnsi(buffer).split("\n")) {
    const line = raw.trim();
    if (!line.startsWith("{")) continue;
    try {
      const j = JSON.parse(line);
      if (j && j.protocol && j.timestamp) {
        const req = typeof j["raw-request"] === "string" ? j["raw-request"].split(/\r?\n/)[0] : null;
        out.push({
          protocol: j.protocol,
          remote_address: j["remote-address"] ?? null,
          request_line: req,
          timestamp: j.timestamp,
          unique_id: j["unique-id"] ?? null,
        });
      }
    } catch {
      /* non-JSON banner/status line — ignore */
    }
  }
  return out;
}

function localIP(): string {
  const ifaces = networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] ?? []) {
      if (iface.family === "IPv4" && !iface.internal) return iface.address;
    }
  }
  return "127.0.0.1";
}

function result(s: OobSession, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: s.id,
    mode: s.mode,
    domain: s.domain ?? null,
    url: s.url ?? null,
    payload_url: s.url ? `\${oob_url}` : null,
    payload_dns: s.domain ? `\${oob_dns}` : null,
    templates: s.domain
      ? {
          dns: `\${oob_dns}`,
          http: `http://\${oob_dns}`,
          ssrf_xxe: `http://\${oob_dns}/<marker>`,
          sql_blind: `http://\${oob_dns}/<marker>`,
        }
      : { http: `http://${s.url}/<marker>` },
    ...extra,
  };
}

/** Start an OOB listener. Returns the callback URL/domain + payload templates. */
export async function oobStart(): Promise<Record<string, unknown>> {
  const bin = findInteractsh();
  if (bin) {
    const id = randomUUID().slice(0, 8);
    const session: OobSession = { id, mode: "interactsh", buffer: "", hits: [], startedAt: Date.now() };
    session.proc = spawn(bin, ["-json"], { stdio: ["ignore", "pipe", "pipe"] });
    session.proc.stdout?.on("data", (d) => (session.buffer += d.toString()));
    session.proc.stderr?.on("data", (d) => (session.buffer += d.toString()));
    sessions.set(id, session);

    // Wait (deterministic, bounded) for the client to register its domain.
    // interactsh registers against several servers + runs a version check, so
    // this can take ~15-20s on first run.
    const deadline = Date.now() + 25000;
    while (Date.now() < deadline) {
      const domain = extractDomain(session.buffer);
      if (domain) {
        session.domain = domain;
        session.url = `http://${domain}`;
        return result(session, { status: "listening" });
      }
      await sleep(300);
    }
    return result(session, { status: "timeout", note: "interactsh-client did not register a domain within 15s — check network / oast server reachability" });
  }
  return startSelfHost();
}

function startSelfHost(): Record<string, unknown> {
  const id = randomUUID().slice(0, 8);
  const session: OobSession = { id, mode: "selfhost", buffer: "", hits: [], startedAt: Date.now() };
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      session.hits.push({
        protocol: "http",
        method: req.method,
        path: req.url,
        remote_address: req.socket.remoteAddress,
        headers: req.headers,
        body: body.slice(0, 2000),
        timestamp: new Date().toISOString(),
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("oob-ok");
    });
  });
  server.listen(0, "0.0.0.0");
  const port = (server.address() as { port: number }).port;
  session.server = server;
  session.port = port;
  session.url = `http://${localIP()}:${port}`;
  sessions.set(id, session);
  return result(session, {
    status: "listening",
    note: "local listener (target must reach this host); for a remote target, expose it via a tunnel (e.g. pinggy) and re-point the payload",
  });
}

/** Poll an OOB session for incoming interactions. Deterministic — only reports
 *  interactions actually received for this session's unique id. */
export function oobPoll(id: string): Record<string, unknown> {
  const s = sessions.get(id);
  if (!s) return { error: "unknown session id (was it stopped or did the server restart?)" };

  if (s.mode === "selfhost") {
    const fresh = s.hits.slice(0);
    s.hits.length = 0;
    return { id, mode: s.mode, url: s.url, found: fresh.length > 0, hits: fresh, total_hits_seen: fresh.length };
  }

  // interactsh: parse JSONL interactions + diff against what we've already reported.
  const interactions = parseInteractions(s.buffer);
  const known = new Set(s.hits.map((h) => `${h.timestamp}|${h.protocol}|${h.request_line ?? ""}`));
  const fresh = interactions.filter((i) => !known.has(`${i.timestamp}|${i.protocol}|${i.request_line ?? ""}`));
  s.hits.push(...fresh);
  return { id, mode: s.mode, domain: s.domain, url: s.url, found: fresh.length > 0, hits: fresh, total_hits_seen: s.hits.length };
}

/** Stop an OOB session + free its resources (kill interactsh child / close server). */
export function oobStop(id: string): Record<string, unknown> {
  const s = sessions.get(id);
  if (!s) return { error: "unknown session id" };
  try {
    s.proc?.kill("SIGTERM");
  } catch {
    /* already dead */
  }
  try {
    s.server?.close();
  } catch {
    /* already closed */
  }
  sessions.delete(id);
  return { id, stopped: true, total_hits_seen: s.hits.length };
}

/** List active OOB sessions (for introspection). */
export function oobList(): Record<string, unknown> {
  return { active: [...sessions.values()].map((s) => ({ id: s.id, mode: s.mode, domain: s.domain, url: s.url, age_sec: Math.round((Date.now() - s.startedAt) / 1000) })) };
}
