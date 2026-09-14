/** Shared HTTP helpers — responsible-disclosure header injection.
 *
 * When an operator sets the H1_USERNAME environment variable, every outbound
 * security-testing request carries:
 *
 *   X-HackerOne-Research: <username>
 *
 * This identifies the researcher to the target and triagers, which is the
 * expected convention for coordinated/authorized security research (HackerOne
 * scope). When H1_USERNAME is unset, no header is added and behaviour is
 * unchanged.
 */

/** The X-HackerOne-Research header (or an empty object when unconfigured). */
export function researchHeaders(): Record<string, string> {
  const u = process.env.H1_USERNAME?.trim();
  return u ? { "X-HackerOne-Research": u } : {};
}

/** Merge the research header into an existing header map (never overrides an
 * explicit caller-supplied value). */
export function withResearchHeaders(headers?: Record<string, string>): Record<string, string> {
  return { ...researchHeaders(), ...(headers ?? {}) };
}

/** Current configured H1 username ("" when unset) — for doctor / diagnostics. */
export function h1Username(): string {
  return process.env.H1_USERNAME?.trim() ?? "";
}
