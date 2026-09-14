/** Asset discovery — full passive asset enumeration for a domain.
 *
 *  Combines certificate-transparency subdomain enumeration (crt.sh) + common-prefix
 *  DNS brute + best-effort A-record resolution into one clean asset map, so the
 *  agent gets every host under a domain before choosing where to strike.
 */
import { subdomainEnum, dnsBrute, scanPorts } from "./live-recon.js";
import { resolve4 } from "node:dns/promises";

function normalizeDomain(domain: string): string {
  return domain.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "").trim().toLowerCase();
}

export interface AssetDiscoveryResult {
  domain: string;
  subdomains: string[];
  resolved: Array<{ host: string; ips: string[] }>;
  open_ports: Array<{ port: number; service: string }>;
  source: string;
  total: number;
}

export async function assetDiscovery(domain: string, includePorts = false): Promise<AssetDiscoveryResult> {
  const d = normalizeDomain(domain);
  if (!d || !d.includes(".")) return { domain: d, subdomains: [], resolved: [], open_ports: [], source: "invalid domain", total: 0 };

  const [ct, brute] = await Promise.all([subdomainEnum(d), dnsBrute(d)]);
  const hosts = [...new Set([...ct.subdomains, ...brute.found.map((f) => f.host), d])].sort();

  // Resolve every host (best-effort, bounded concurrency) — skip CDN-heavy noise.
  const resolved: Array<{ host: string; ips: string[] }> = [];
  const CHUNK = 10;
  for (let i = 0; i < hosts.length; i += CHUNK) {
    const batch = hosts.slice(i, i + CHUNK);
    await Promise.all(
      batch.map(async (host) => {
        try {
          const ips = await resolve4(host);
          if (ips.length) resolved.push({ host, ips });
        } catch {
          /* non-resolving host — skip */
        }
      }),
    );
  }

  let open_ports: Array<{ port: number; service: string }> = [];
  if (includePorts) {
    const main = resolved.find((r) => r.host === d) ?? resolved[0];
    if (main) {
      const scan = await scanPorts(main.ips[0] ?? main.host);
      open_ports = scan.filter((p) => p.open).map((p) => ({ port: p.port, service: p.service }));
    }
  }

  return {
    domain: d,
    subdomains: hosts,
    resolved,
    open_ports,
    source: `${ct.source} + ${brute.source}`,
    total: hosts.length,
  };
}
