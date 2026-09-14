/** Hunting doctrine + always-rejected kill-list — LLM-facing methodology.
 *
 *  Blitz Strike's detectors are deterministic; but PAYOUT is won or lost by
 *  WHERE and HOW the agent hunts. This module encodes the high-ROI hunting
 *  heuristics (sibling rule, A→B signal, follow-the-money, …) + the
 *  always-rejected list (weak findings that must be killed before reporting).
 *
 *  Source: cross-referenced with leading bug-bounty methodology.
 *  Deterministic data, not LLM guesswork.
 */

export interface RejectedClass {
  type: string;
  reason: string;
}

/** Findings that are always N/A (or informational) standalone — kill before
 *  spending time on a report. Chain them to real impact first. */
export const ALWAYS_REJECTED: RejectedClass[] = [
  { type: "missing_headers", reason: "CSP / HSTS / X-Frame-Options headers alone — never accepted standalone." },
  { type: "graphql_introspection", reason: "GraphQL introspection alone — informational; it only maps the attack surface." },
  { type: "self_xss", reason: "Self-XSS — the attacker can only execute against themselves." },
  { type: "open_redirect", reason: "Open redirect alone — informational without an OAuth/token-theft chain." },
  { type: "ssrf_dns_only", reason: "SSRF with a DNS callback only — no data read, no impact." },
  { type: "logout_csrf", reason: "Logout CSRF — no security impact." },
  { type: "missing_cookie_flags", reason: "Missing cookie flags (Secure/HttpOnly/SameSite) alone — informational." },
  { type: "rate_limit_noncritical", reason: "Rate-limit on a non-critical form — informational." },
  { type: "version_disclosure", reason: "Banner/version disclosure without a working exploit." },
];

function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_");
}

/** Deterministic always-rejected check. Pass a free-form finding type (or omit to
 *  enumerate the full list). Returns rejected:true when the type is a known weak
 *  class — kill it (or chain it to real impact) before reporting. */
export function killList(type?: string): { rejected: boolean; matches: RejectedClass[] } {
  if (!type) return { rejected: false, matches: ALWAYS_REJECTED };
  const t = norm(type);
  const matches = ALWAYS_REJECTED.filter((x) => {
    const n = norm(x.type);
    return t.includes(n) || n.includes(t);
  });
  return { rejected: matches.length > 0, matches };
}

export interface DoctrineRule {
  id: string;
  title: string;
  rule: string;
}

/** The hunting doctrine — the high-ROI heuristics the agent applies while
 *  selecting targets, endpoints, and bug classes. */
export const HUNTING_DOCTRINE: DoctrineRule[] = [
  {
    id: "sibling_rule",
    title: "The Sibling Rule",
    rule: "Check EVERY sibling endpoint. If /api/user/123/orders requires auth, also check /api/user/123/export, /delete, /share. This explains ~30% of all paid IDOR/auth bugs.",
  },
  {
    id: "a_b_signal",
    title: "A→B Signal Method",
    rule: "When bug A is confirmed, STOP and hunt B and C before writing the report. A confirmed bug signals a class of developer mistake — finding B costs 10x less than finding A. Time-box 20 minutes; if B is not confirmed, submit A and move on.",
  },
  {
    id: "impact_first",
    title: "Impact-First",
    rule: "Ask 'what is the worst thing that happens if auth/validation is broken HERE?' — nothing valuable → skip. Admin/PII/fund-theft → hunt.",
  },
  {
    id: "follow_money",
    title: "Follow the Money",
    rule: "Billing / credits / refunds / wallet flows have the most developer shortcuts. Price manipulation, payment races, quota bypass = high ROI.",
  },
  {
    id: "less_saturated",
    title: "Hunt Less-Saturated Classes",
    rule: "High competition (skip unless target-specific): XSS, SSRF basics, open redirect alone. Low competition: cache poisoning, race conditions, business logic, HTTP request smuggling, CI/CD.",
  },
  {
    id: "new_unreviewed",
    title: "New == Unreviewed",
    rule: "Features <30 days old have the lowest security maturity. Monitor commits; hunt new features first.",
  },
  {
    id: "two_account",
    title: "Two-Account IDOR Test",
    rule: "Never test IDOR with one account. Account A = attacker (your request), Account B = victim (whose data you read). The report must state: 'sent Account A's token with Account B's id and received Account B's data.'",
  },
  {
    id: "poc_escalation",
    title: "PoC Escalation",
    rule: "IDOR → show the victim's actual data (not just 200 OK). XSS → show cookie exfiltration (not alert). SSRF → show the internal service response (not just a DNS callback). SQLi → show real database content (not just an error).",
  },
  {
    id: "credential_proof",
    title: "Credential Leaks Need Exploitation Proof",
    rule: "An API key alone is Informational. Prove what it accesses (S3 read, DB, admin panel) via validate_leaked_key — then it is Medium/High.",
  },
  {
    id: "cicd_surface",
    title: "CI/CD Is Attack Surface",
    rule: "GitHub Actions / GitLab CI hold critical secrets. Check public repos BEFORE reporting: pull_request_target + checkout of the PR branch (attacker code runs with repo secrets), ${{github.event.issue.title}} in a run: block (expression injection → secret exfil), artifact download without hash check.",
  },
  {
    id: "saml_sso",
    title: "SAML / SSO = Highest Auth Bug Density",
    rule: "If the target uses SSO, test: XML signature wrapping (XSW), comment injection (admin<!---->@company.com), signature stripping, NameID manipulation in the unsigned field. SAML bugs pay High–Critical (SSO bypass across the platform).",
  },
  {
    id: "rotation",
    title: "20-Minute Rotation",
    rule: "Every 20 minutes ask 'am I making progress?'. No → rotate to the next endpoint / subdomain / class. Fresh context finds more bugs than brute force.",
  },
];

/** Full hunting doctrine (for the `hunting_doctrine` tool). */
export function huntingDoctrine(): Record<string, unknown> {
  return {
    doctrine: HUNTING_DOCTRINE,
    always_rejected: ALWAYS_REJECTED,
  };
}
