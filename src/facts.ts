/** Observation ledger + lineage — the third write-back channel.
 *
 *  Simple: an observation ("fact") is a free-text conclusion from exploration that
 *  is NOT a vuln (finding_create) and NOT an asset (asset_discovery) — e.g. "the
 *  admin panel is behind SSO", "the upload endpoint strips .php", "param `id` is
 *  reflected in the error page". Each fact carries an honest confidence
 *  (observed = directly triggered vs inferred = deduced from a fingerprint/diff)
 *  and optional parent_ids so facts can chain into a lineage: where a conclusion
 *  came from, and what it produced.
 */

export type Confidence = "observed" | "inferred";

/** Typed lineage-edge vocabulary — how a fact relates to the fact(s) it derives
 *  from. Mirrors the attack-graph edge types of graph-backed agents so the lineage
 *  is navigable as a typed graph, not a flat "derived-from" chain. */
export const FACT_EDGE_TYPES = [
  "derives_from", // default: a conclusion deduced from another fact
  "yielded_access", // the fact produced a foothold/access from its parent
  "escalated_via", // privilege escalation over the parent context
  "pivoted_to", // lateral movement / new host reached via the parent
  "authenticates_to", // a credential/account fact authenticates to a target
  "attempted_on", // an attempt was made against the parent target
] as const;
export type FactEdge = (typeof FACT_EDGE_TYPES)[number];

export interface Fact {
  id: string;
  text: string;
  confidence: Confidence;
  /** Optional target (host/endpoint/param) the observation is about. */
  target?: string;
  /** Lineage: ids of the facts this one derives from. */
  parent_ids: string[];
  /** Typed relationship to the parent(s) (see FACT_EDGE_TYPES). */
  rel: FactEdge;
  created: string;
}

let facts: Fact[] = [];
let counter = 0;

function nextId(): string {
  counter += 1;
  return `FACT-${String(counter).padStart(3, "0")}`;
}

/** Record an observation. Returns the stored fact. */
export function recordFact(input: {
  text: string;
  confidence: Confidence;
  target?: string;
  parent_ids?: string[];
  rel?: FactEdge;
}): Fact {
  const fact: Fact = {
    id: nextId(),
    text: input.text,
    confidence: input.confidence,
    target: input.target,
    parent_ids: input.parent_ids ?? [],
    rel: input.rel ?? "derives_from",
    created: new Date().toISOString(),
  };
  facts.push(fact);
  return fact;
}

/** List every recorded fact. */
export function listFacts(): Fact[] {
  return [...facts];
}

/** Walk the lineage of a fact: its ancestors (parents up) and descendants (children down). */
export function lineage(id: string): { fact?: Fact; ancestors: Fact[]; descendants: Fact[] } | { error: string } {
  const fact = facts.find((f) => f.id === id);
  if (!fact) return { error: `no fact '${id}'` };
  const ancestors: Fact[] = [];
  const seen = new Set<string>([id]);
  const queue = [...fact.parent_ids];
  while (queue.length) {
    const pid = queue.shift()!;
    if (seen.has(pid)) continue;
    seen.add(pid);
    const p = facts.find((f) => f.id === pid);
    if (p) { ancestors.push(p); queue.push(...p.parent_ids); }
  }
  const descendants = facts.filter((f) => f.parent_ids.includes(id));
  return { fact, ancestors, descendants };
}
