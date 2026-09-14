/** Surface coverage tracker — the quantitative "how done are we" measure.
 *
 *  Tracks the discovered attack surface (endpoints/params/hosts/subdomains/routes/
 *  classes) and, for each item, whether it has a terminal verdict (confirmed / dead
 *  / partial / skipped). `pct` = terminal / total — an objective progress number
 *  that complements the qualitative exhaustion checklist and makes a goal like
 *  "coverage >= 80%" actually measurable.
 */

export type SurfaceKind = "endpoint" | "param" | "host" | "subdomain" | "route" | "class";
export type SurfaceVerdict = "confirmed" | "dead" | "partial" | "skipped";

export interface SurfaceItem {
  id: string;
  kind: SurfaceKind;
  /** The endpoint/param/host/etc. this item refers to (e.g. "/api/users", "id", "app.example.com"). */
  ref: string;
  /** Terminal verdict, or null = still pending. */
  verdict: SurfaceVerdict | null;
  updated: string;
}

let surface: SurfaceItem[] = [];
let counter = 0;

function nextId(): string {
  counter += 1;
  return `SRF-${String(counter).padStart(4, "0")}`;
}

/** Register a discovered surface item (deduped by kind+ref). Returns the item. */
export function surfaceAdd(kind: SurfaceKind, ref: string): SurfaceItem {
  const existing = surface.find((s) => s.kind === kind && s.ref === ref);
  if (existing) return existing;
  const item: SurfaceItem = { id: nextId(), kind, ref, verdict: null, updated: new Date().toISOString() };
  surface.push(item);
  return item;
}

/** Mark a terminal verdict on a surface item (by id or by kind+ref). */
export function surfaceVerdict(idOrRef: string, verdict: SurfaceVerdict): { ok: boolean; item?: SurfaceItem; error?: string } {
  const item = surface.find((s) => s.id === idOrRef || s.ref === idOrRef);
  if (!item) return { ok: false, error: `no surface item '${idOrRef}'` };
  item.verdict = verdict;
  item.updated = new Date().toISOString();
  return { ok: true, item: { ...item } };
}

/** The coverage summary: how much of the discovered surface has a terminal verdict. */
export function coverageSummary(): {
  total: number;
  terminal: number;
  pending: number;
  pct: number;
  by_kind: Record<SurfaceKind, { total: number; terminal: number }>;
  by_verdict: Record<SurfaceVerdict, number>;
} {
  const by_kind: Record<SurfaceKind, { total: number; terminal: number }> = {
    endpoint: { total: 0, terminal: 0 },
    param: { total: 0, terminal: 0 },
    host: { total: 0, terminal: 0 },
    subdomain: { total: 0, terminal: 0 },
    route: { total: 0, terminal: 0 },
    class: { total: 0, terminal: 0 },
  };
  const by_verdict: Record<SurfaceVerdict, number> = { confirmed: 0, dead: 0, partial: 0, skipped: 0 };
  let terminal = 0;
  for (const s of surface) {
    by_kind[s.kind].total += 1;
    if (s.verdict) {
      terminal += 1;
      by_kind[s.kind].terminal += 1;
      by_verdict[s.verdict] += 1;
    }
  }
  const total = surface.length;
  return {
    total,
    terminal,
    pending: total - terminal,
    pct: total === 0 ? 0 : Math.round((terminal / total) * 1000) / 10,
    by_kind,
    by_verdict,
  };
}
