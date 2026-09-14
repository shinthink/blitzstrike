/** `proto_pollution_probe` — live prototype-pollution detector (evidence-first).
 *
 *  Sends deterministic pollution payloads (JSON __proto__ / constructor.prototype
 *  / merge-style) and checks for a canary side-effect. The verdict is DERIVED:
 *  VERIFIED only when the canary is actually reflected back — never from a
 *  "payload was accepted" guess.
 */
const CANARY = "blitzstrike_pollution_canary_9f3a";

export interface ProtoPollutionResult {
  status: "verified" | "unverified" | "error";
  message?: string;
  probes: Array<{ kind: string; http_status?: number; reflected: boolean; note: string }>;
}

export async function protoPollutionProbe(opts: {
  target: string;
  endpoint?: string;
  method?: string;
  param?: string;
}): Promise<ProtoPollutionResult> {
  if (!/^https?:\/\//i.test(opts.target)) {
    return { status: "error", message: "target must be an http(s) URL", probes: [] };
  }
  const method = (opts.method ?? "POST").toUpperCase();
  const param = opts.param ?? "data";

  let full: string;
  if (opts.endpoint && /^https?:\/\//i.test(opts.endpoint)) {
    full = opts.endpoint;
  } else {
    const path = opts.endpoint ?? "";
    full = `${opts.target.replace(/\/$/, "")}${path.startsWith("/") ? "" : "/"}${path}`;
  }

  const kinds: Array<[string, string]> = [
    ["proto", JSON.stringify({ [param]: { __proto__: { polluted: CANARY } } })],
    ["constructor", JSON.stringify({ [param]: { constructor: { prototype: { polluted: CANARY } } } })],
    ["proto_direct", JSON.stringify({ __proto__: { polluted: CANARY } })],
    ["constructor_direct", JSON.stringify({ constructor: { prototype: { polluted: CANARY } } })],
  ];

  const probes: ProtoPollutionResult["probes"] = [];
  for (const [kind, body] of kinds) {
    try {
      const res = await fetch(full, { method, headers: { "Content-Type": "application/json" }, body });
      const text = await res.text();
      const reflected = text.includes(CANARY) || text.includes("polluted");
      probes.push({ kind, http_status: res.status, reflected, note: reflected ? "canary reflected in response" : "no reflection" });
    } catch (e) {
      probes.push({ kind, http_status: -1, reflected: false, note: String((e as Error).message) });
    }
  }

  const verified = probes.some((p) => p.reflected);
  return {
    status: verified ? "verified" : "unverified",
    message: verified ? "pollution canary reflected — prototype pollution confirmed" : "no reflection observed (pollution may still occur server-side — confirm with a follow-up request that observes the polluted property)",
    probes,
  };
}
