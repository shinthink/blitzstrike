/** `smuggling_test` — live HTTP request-smuggling (desync) detector.
 *
 *  Sends CL.TE and TE.CL probes over a single raw connection and compares the
 *  follow-up request's response against a clean baseline. A desync is FLAGGED
 *  only on a SPECIFIC signal — the smuggled prefix actually corrupted the next
 *  request's method (a 405 Method-Not-Allowed, or a "GGET"/"GPOST" error in the
 *  follow-up body) — never from a generic 400 on the malformed probe itself.
 *  The verdict is derived from the wire, and a signal is still a HINT to verify
 *  with the full smuggled-request chain before reporting.
 */
import { connect } from "node:net";
import { connect as tlsConnect } from "node:tls";

interface WireResult {
  statuses: number[];
  body: string;
}

function rawRound(host: string, port: number, tls: boolean, chunks: string[]): Promise<WireResult> {
  return new Promise((resolve) => {
    const sock = tls ? tlsConnect({ host, port, rejectUnauthorized: false }) : connect({ host, port });
    let buf = "";
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      sock.destroy();
      const statuses = [...buf.matchAll(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/gm)].map((m) => parseInt(m[1], 10));
      resolve({ statuses, body: buf });
    };
    sock.setTimeout(8000, finish);
    sock.on("connect", () => {
      for (const c of chunks) sock.write(c);
    });
    sock.on("data", (d) => {
      buf += d.toString();
    });
    sock.on("end", finish);
    sock.on("close", finish);
    sock.on("error", finish);
  });
}

export interface SmugglingResult {
  status: "desync" | "no_desync" | "error";
  message?: string;
  baseline: number;
  probes: Array<{ type: "CL.TE" | "TE.CL"; probe_status: number; follow_up_status: number | null; desync: boolean; note: string }>;
}

// A desync is only asserted when the follow-up response shows a corrupted method.
function isCorrupted(body: string, status: number | null): boolean {
  return status === 405 || /GGET|GPOST|GPUT|GDELETE|unrecognized method|invalid method/i.test(body);
}

export async function smugglingTest(target: string): Promise<SmugglingResult> {
  let u: URL;
  try {
    u = new URL(target);
  } catch {
    return { status: "error", message: `invalid URL: ${target}`, baseline: -1, probes: [] };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { status: "error", message: "target must be http(s)", baseline: -1, probes: [] };
  }
  const host = u.hostname;
  const port = u.port ? parseInt(u.port, 10) : u.protocol === "https:" ? 443 : 80;
  const tls = u.protocol === "https:";
  const hostHeader = u.port ? `${host}:${u.port}` : host;

  const baselineReq = `GET / HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n\r\n`;
  const baseline = await rawRound(host, port, tls, [baselineReq]);
  const baselineStatus = baseline.statuses[0] ?? -1;

  const clteProbe = `POST / HTTP/1.1\r\nHost: ${hostHeader}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG`;
  const teclProbe = `POST / HTTP/1.1\r\nHost: ${hostHeader}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: ${hostHeader}\r\nContent-Length: 5\r\n\r\nx=1\r\n0\r\n\r\n`;

  const probes: SmugglingResult["probes"] = [];

  const clteRes = await rawRound(host, port, tls, [clteProbe, baselineReq]);
  const clteFollow = clteRes.statuses[1] ?? null;
  const clteDesync = isCorrupted(clteRes.body, clteFollow);
  probes.push({ type: "CL.TE", probe_status: clteRes.statuses[0] ?? -1, follow_up_status: clteFollow, desync: clteDesync, note: clteDesync ? "follow-up method corrupted (405 / GGET-GPOST) — CL.TE desync likely" : `follow-up ${clteFollow ?? "none"} — no corruption` });

  const teclRes = await rawRound(host, port, tls, [teclProbe, baselineReq]);
  const teclFollow = teclRes.statuses[1] ?? null;
  const teclDesync = isCorrupted(teclRes.body, teclFollow);
  probes.push({ type: "TE.CL", probe_status: teclRes.statuses[0] ?? -1, follow_up_status: teclFollow, desync: teclDesync, note: teclDesync ? "follow-up method corrupted (405 / GGET-GPOST) — TE.CL desync likely" : `follow-up ${teclFollow ?? "none"} — no corruption` });

  const desync = clteDesync || teclDesync;
  return {
    status: desync ? "desync" : "no_desync",
    message: desync ? "request-smuggling desync detected — verify manually with the full CL.TE/TE.CL chain before reporting" : "no method-corruption observed (single-round probe; a full smuggled-request chain may still be needed)",
    baseline: baselineStatus,
    probes,
  };
}
