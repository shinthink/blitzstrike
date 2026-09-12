/** Intelligence data layer — WAF signatures, tech/CVE correlations, ports, fuzzers.
 *
 * Loads the JSON data files (sourced from airecon, MIT) and exposes lookup +
 * enrichment helpers. This is the enrichment data layer BlitzStrike previously
 * lacked.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const INTEL = join(ROOT, "intelligence");

function loadJson<T>(name: string): T | null {
  const p = join(INTEL, `${name}.json`);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as T;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Typed data shapes
// ---------------------------------------------------------------------------

interface WafSignature {
  waf: string;
  header?: string;
  pattern?: string;
  confidence: number;
}

interface WafSignatures {
  header_signatures: WafSignature[];
  body_signatures: WafSignature[];
  block_status_codes: number[];
}

interface TechEntry {
  vulns?: string[];
  paths?: string[];
  detection?: Record<string, unknown>;
}

type TechCorrelations = Record<string, TechEntry>;

interface CveEntry {
  name?: string;
  product?: string;
  severity?: string;
  description?: string;
  [key: string]: unknown;
}

type CveCorrelations = Record<string, CveEntry>;

interface PortEntry {
  service?: string;
  vulns?: string[];
  [key: string]: unknown;
}

type PortCorrelations = Record<string, PortEntry>;

type FuzzerData = Record<string, string[]>;

interface AttackVectorCategory {
  id: string;
  title: string;
  vectors: string[];
  focus?: string;
}

interface AttackVectorsData {
  categories: AttackVectorCategory[];
}

// ---------------------------------------------------------------------------
// WAF detection
// ---------------------------------------------------------------------------

export interface WafMatch {
  waf: string;
  header?: string;
  pattern?: string;
  confidence: number;
  via?: string;
}

export interface WafDetection {
  detected: boolean;
  wafs: WafMatch[];
  block_status_codes?: number[];
  error?: string;
}

export function detectWaf(headers: Record<string, string>, body = ""): WafDetection {
  const sigs = loadJson<WafSignatures>("waf_signatures");
  if (!sigs) return { detected: false, wafs: [], error: "waf_signatures.json not loaded" };

  const headerSigs = sigs.header_signatures ?? [];
  const bodySigs = sigs.body_signatures ?? [];

  const matches: WafMatch[] = [];
  const headerKeys = Object.keys(headers).map((k) => k.toLowerCase());

  for (const s of headerSigs) {
    const h = (s.header ?? "").toLowerCase();
    const pattern = (s.pattern ?? "").toLowerCase();
    if (!h) continue;
    if (pattern) {
      // pattern present: match against the VALUE of that specific header
      const val = (headers[h] ?? headers[s.header ?? ""] ?? "").toLowerCase();
      if (val.includes(pattern)) {
        matches.push({ waf: s.waf, header: s.header, pattern: s.pattern, confidence: s.confidence, via: "header-value" });
      }
    } else {
      // no pattern: match by header NAME presence only
      if (headerKeys.includes(h)) {
        matches.push({ waf: s.waf, header: s.header, confidence: s.confidence, via: "header-name" });
      }
    }
  }
  for (const s of bodySigs) {
    const pattern = (s.pattern ?? "").toLowerCase();
    if (pattern && body.toLowerCase().includes(pattern)) {
      matches.push({ waf: s.waf, pattern: s.pattern, confidence: s.confidence, via: "body" });
    }
  }

  // dedupe by waf name, keep highest confidence
  const byWaf = new Map<string, WafMatch>();
  for (const m of matches) {
    const key = m.waf;
    const prev = byWaf.get(key);
    if (!prev || m.confidence > prev.confidence) byWaf.set(key, m);
  }

  const detected = [...byWaf.values()].sort((a, b) => b.confidence - a.confidence);
  return {
    detected: detected.length > 0,
    wafs: detected,
    block_status_codes: sigs.block_status_codes ?? [],
  };
}

// ---------------------------------------------------------------------------
// Tech correlation
// ---------------------------------------------------------------------------

export interface TechCorrelationResult {
  found: boolean;
  tech?: string;
  vulns?: string[];
  paths?: string[];
  detection?: Record<string, unknown>;
  suggestions?: string[];
  error?: string;
}

export function techCorrelation(tech: string): TechCorrelationResult {
  const data = loadJson<TechCorrelations>("tech_correlations");
  if (!data) return { found: false, error: "tech_correlations.json not loaded" };
  const key = tech.toLowerCase();
  const entry = data[key];
  if (!entry) {
    const matches = Object.keys(data).filter((k) => k.includes(key) || key.includes(k)).slice(0, 5);
    return { found: false, tech, suggestions: matches };
  }
  return { found: true, tech: key, vulns: entry.vulns ?? [], paths: entry.paths ?? [], detection: entry.detection ?? { vulns: entry.vulns, paths: entry.paths } };
}

// ---------------------------------------------------------------------------
// CVE correlation
// ---------------------------------------------------------------------------

export function cveCorrelation(cveId: string): Record<string, unknown> {
  const data = loadJson<CveCorrelations>("cve_correlations");
  if (!data) return { error: "cve_correlations.json not loaded" };
  const key = cveId.toUpperCase();
  const entry = data[key];
  if (!entry) return { found: false, cve: key, total_known: Object.keys(data).length };
  return { found: true, cve: key, ...entry };
}

// ---------------------------------------------------------------------------
// Port correlation
// ---------------------------------------------------------------------------

export function portCorrelation(port: string | number): Record<string, unknown> {
  const data = loadJson<PortCorrelations>("port_correlations");
  if (!data) return { error: "port_correlations.json not loaded" };
  const key = String(port);
  const entry = data[key];
  if (!entry) return { found: false, port: key, total_known: Object.keys(data).length };
  return { found: true, port: key, ...entry };
}

// ---------------------------------------------------------------------------
// Fuzzer data
// ---------------------------------------------------------------------------

export function fuzzerPayloads(category?: string): Record<string, unknown> {
  const data = loadJson<FuzzerData>("fuzzer_data");
  if (!data) return { error: "fuzzer_data.json not loaded" };
  if (category) {
    const c = data[category] ?? data[category.toUpperCase()];
    return { category, found: Boolean(c), data: c ?? null };
  }
  return { categories: Object.keys(data), fuzz_points: data.FUZZ_POINTS ?? null, payloads: data.FUZZ_PAYLOADS ?? null };
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function intelSummary(): Record<string, unknown> {
  const waf = loadJson<WafSignatures>("waf_signatures");
  const tech = loadJson<TechCorrelations>("tech_correlations");
  const cve = loadJson<CveCorrelations>("cve_correlations");
  const port = loadJson<PortCorrelations>("port_correlations");
  const fuzz = loadJson<FuzzerData>("fuzzer_data");
  const av = loadJson<AttackVectorsData>("attack_vectors");
  return {
    waf_signatures: waf ? (waf.header_signatures?.length ?? 0) + (waf.body_signatures?.length ?? 0) : 0,
    tech_correlations: tech ? Object.keys(tech).length : 0,
    cve_correlations: cve ? Object.keys(cve).length : 0,
    port_correlations: port ? Object.keys(port).length : 0,
    fuzzer_categories: fuzz ? Object.keys(fuzz).length : 0,
    payload_categories: listPayloadCategories().length,
    nuclei_templates: countTemplates(),
    attack_vector_categories: av ? av.categories.length : 0,
    attack_vectors: av ? av.categories.reduce((n, c) => n + c.vectors.length, 0) : 0,
  };
}

// ---------------------------------------------------------------------------
// Attack-vector taxonomy (BLITZ attack-surface mapping)
// ---------------------------------------------------------------------------

/** List all attack-vector categories with counts (the master taxonomy). */
export function listAttackVectors(): Record<string, unknown> {
  const data = loadJson<AttackVectorsData>("attack_vectors");
  if (!data) return { error: "attack_vectors.json not loaded" };
  return {
    total_categories: data.categories.length,
    total_vectors: data.categories.reduce((n, c) => n + c.vectors.length, 0),
    categories: data.categories.map((c) => ({ id: c.id, title: c.title, count: c.vectors.length, focus: c.focus ?? "" })),
  };
}

/** Return the full vector list for a category (by id or fuzzy title match). */
export function attackVectors(category: string): Record<string, unknown> {
  const data = loadJson<AttackVectorsData>("attack_vectors");
  if (!data) return { error: "attack_vectors.json not loaded" };
  const q = category.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  const found = data.categories.find(
    (c) => c.id === q || c.id.includes(q) || c.title.toLowerCase().includes(category.toLowerCase()),
  );
  if (!found) {
    const matches = data.categories
      .filter((c) => c.title.toLowerCase().includes(category.toLowerCase()) || c.id.includes(q))
      .slice(0, 5)
      .map((c) => c.id);
    return { found: false, query: category, suggestions: matches };
  }
  return { found: true, id: found.id, title: found.title, focus: found.focus ?? "", count: found.vectors.length, vectors: found.vectors };
}

// ---------------------------------------------------------------------------
// Attack-vector decision support — turn recon context (tech + params) into a
// prioritized plan of what to test, so the driving agent decides with data
// instead of guessing. Base injection vectors are always listed; then param
// hints and tech hints add + reprioritize.
// ---------------------------------------------------------------------------

const BASE_VECTORS: Array<{ vector: string; priority: number; reason: string; tool: string }> = [
  { vector: "sql_injection", priority: 2, reason: "any parameter that reaches a SQL query", tool: "run_engagement (SQLi check) / strike_verify" },
  { vector: "xss", priority: 2, reason: "any reflected/stored output", tool: "run_engagement (XSS check) / strike_verify" },
  { vector: "command_injection", priority: 2, reason: "any parameter passed to a shell/exec", tool: "run_engagement (command-injection check)" },
  { vector: "ssti", priority: 2, reason: "template engines render user input", tool: "run_engagement (SSTI check)" },
  { vector: "ssrf", priority: 2, reason: "any URL/redirect/webhook/fetch parameter", tool: "run_engagement (SSRF check)" },
  { vector: "idor", priority: 3, reason: "any object-id parameter (missing object-level auth)", tool: "strike_verify" },
  { vector: "path_traversal", priority: 3, reason: "any file/path parameter", tool: "run_engagement (traversal check)" },
  { vector: "open_redirect", priority: 3, reason: "any redirect/url parameter", tool: "run_engagement (redirect check)" },
  { vector: "xxe", priority: 3, reason: "XML input", tool: "complex_scan" },
  { vector: "file_upload", priority: 3, reason: "any upload endpoint", tool: "read_skill + upload->RCE chain" },
  { vector: "cors_misconfiguration", priority: 4, reason: "cross-origin policy", tool: "run_engagement (CORS check)" },
  { vector: "auth_bypass", priority: 3, reason: "any authentication boundary", tool: "read_skill(bs-web-hunting)" },
  { vector: "business_logic", priority: 4, reason: "any state-changing endpoint", tool: "read_skill(hp-business-logic-fuzzing)" },
  { vector: "jwt", priority: 4, reason: "if JWTs are present", tool: "technique_lookup(jwt)" },
];

const PARAM_HINTS: Record<string, string[]> = {
  id: ["idor", "sql_injection"],
  user: ["idor", "sql_injection"],
  username: ["idor", "sql_injection"],
  url: ["ssrf", "open_redirect"],
  uri: ["ssrf"],
  redirect: ["open_redirect", "ssrf"],
  callback: ["ssrf"],
  webhook: ["ssrf"],
  file: ["path_traversal", "file_upload"],
  path: ["path_traversal"],
  cmd: ["command_injection"],
  command: ["command_injection"],
  exec: ["command_injection"],
  q: ["xss", "sql_injection"],
  search: ["xss", "sql_injection"],
  query: ["xss", "sql_injection"],
  name: ["xss", "ssti"],
  template: ["ssti"],
  page: ["xss", "sql_injection"],
};

const TECH_HINTS: Record<string, string[]> = {
  wordpress: ["wp_plugin_audit", "xmlrpc", "rest_api_auth"],
  laravel: ["deserialization", "mass_assignment", "ssti", "debug_mode"],
  php: ["lfi", "upload_rce", "sql_injection"],
  python: ["ssti", "pickle_deserialization"],
  flask: ["ssti"],
  django: ["ssti", "idor"],
  nodejs: ["prototype_pollution", "nosql_injection", "ssti"],
  express: ["prototype_pollution", "nosql_injection"],
  java: ["deserialization", "xxe", "ssti"],
  spring: ["deserialization", "actuator_exposure"],
  aspnet: ["deserialization", "viewstate"],
  nextjs: ["ssrf", "idor"],
};

export function attackPlan(target: string, tech: string[] = [], params: string[] = []): Record<string, unknown> {
  const data = loadJson<AttackVectorsData>("attack_vectors");
  const totalCategories = data?.categories.length ?? 0;
  const plan: Array<{ vector: string; priority: number; reason: string; tool: string; source: string }> =
    BASE_VECTORS.map((v) => ({ ...v, source: "base" }));

  const add = (vector: string, priority: number, reason: string, tool: string, source: string) => {
    const existing = plan.find((p) => p.vector === vector);
    if (existing) {
      existing.priority = Math.min(existing.priority, priority);
      existing.reason += `; ${reason}`;
      existing.source = source;
    } else {
      plan.push({ vector, priority, reason, tool, source });
    }
  };

  for (const p of params) {
    const hints = PARAM_HINTS[p.toLowerCase()] ?? [];
    for (const h of hints) add(h, 1, `param '${p}' suggests ${h}`, "see base vector tool", "param");
  }
  for (const t of tech) {
    const hints = TECH_HINTS[t.toLowerCase()] ?? [];
    for (const h of hints) add(h, 2, `tech '${t}' suggests ${h}`, "technique_lookup / read_skill", "tech");
  }

  const sorted = plan.sort((a, b) => a.priority - b.priority || a.vector.localeCompare(b.vector));
  return {
    target,
    taxonomy: { total_categories: totalCategories, total_vectors_here: sorted.length },
    plan: sorted.map((p, i) => ({
      order: i + 1,
      vector: p.vector,
      priority: p.priority,
      reason: p.reason,
      tool: p.tool,
      source: p.source,
    })),
  };
}

// ---------------------------------------------------------------------------
// Payload collections (PayloadsAllTheThings, MIT) + nuclei templates (MIT)
//
// These heavy datasets (14MB payloads + 66MB templates) are NOT bundled in the
// npm package (npm's malware scanner rejects raw exploit payloads). They are
// resolved from a local cache (~/.blitzstrike/data/) or fetched on-demand from
// the GitHub repo. `blitzstrike sync-data` pre-fetches them.
// ---------------------------------------------------------------------------

import { readdirSync } from "node:fs";
import { homedir } from "node:os";

const PACKAGE_PAYLOADS = join(ROOT, "payloads");
const PACKAGE_TEMPLATES = join(ROOT, "templates");
const DATA_ROOT = process.env.BLITZSTRIKE_DATA ?? join(homedir(), ".blitzstrike", "data");

/** Resolve the payloads dir: package-local if present, else the data cache. */
function payloadsDir(): string {
  if (existsSync(PACKAGE_PAYLOADS)) return PACKAGE_PAYLOADS;
  return join(DATA_ROOT, "payloads");
}

function templatesDir(): string {
  if (existsSync(PACKAGE_TEMPLATES)) return PACKAGE_TEMPLATES;
  return join(DATA_ROOT, "templates");
}

const PAYLOADS = payloadsDir();
const TEMPLATES = templatesDir();

export function listPayloadCategories(): string[] {
  try {
    return readdirSync(PAYLOADS, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort();
  } catch {
    return [];
  }
}

export function payloadLookup(topic: string): Record<string, unknown> {
  const cats = listPayloadCategories();
  const key = topic.toLowerCase();
  // common abbreviation aliases -> full category name
  const ALIASES: Record<string, string> = {
    sqli: "sql injection",
    xss: "xss injection",
    ssrf: "server side request forgery",
    ssti: "server side template injection",
    jwt: "json web token",
    lfi: "file inclusion",
    rfi: "file inclusion",
    xxe: "xxe injection",
    idor: "insecure direct object references",
    csrf: "cross-site request forgery",
    cmdi: "command injection",
    rce: "command injection",
    cors: "cors misconfiguration",
    crlf: "crlf injection",
    prototype: "prototype pollution",
    nosql: "nosql injection",
    upload: "upload insecure files",
  };
  const normalized = ALIASES[key] ?? key;
  // exact match
  const exact = cats.find((c) => c.toLowerCase() === normalized);
  if (exact) {
    return { found: true, category: exact, files: listFiles(join(PAYLOADS, exact)) };
  }
  // fuzzy: category contains topic or vice versa (token-aware)
  const keyTokens = normalized.split(/[^a-z0-9]+/).filter((t) => t.length >= 3);
  const matches = cats.filter((c) => {
    const cl = c.toLowerCase();
    if (cl.includes(normalized) || normalized.includes(cl)) return true;
    return keyTokens.some((tok) => new RegExp(`(^|[^a-z0-9])${tok}`).test(cl));
  });
  if (matches.length > 0) {
    return { found: true, category: matches[0], files: listFiles(join(PAYLOADS, matches[0])), alternatives: matches.slice(0, 10) };
  }
  return { found: false, topic, suggestions: cats.slice(0, 20) };
}

export function readPayload(category: string, file?: string): Record<string, unknown> {
  const cats = listPayloadCategories();
  const exact = cats.find((c) => c.toLowerCase() === category.toLowerCase());
  if (!exact) return { found: false, category, suggestions: cats.slice(0, 20) };
  const dir = join(PAYLOADS, exact);
  const files = listFiles(dir);
  if (!file) {
    // return README if present (the payload collection index)
    const readme = files.find((f) => f.toLowerCase() === "readme.md");
    if (readme) {
      return { found: true, category: exact, file: readme, content: readFileSync(join(dir, readme), "utf8").slice(0, 20000) };
    }
    return { found: true, category: exact, files };
  }
  const f = files.find((x) => x.toLowerCase() === file.toLowerCase());
  if (!f) return { found: false, category: exact, file, suggestions: files };
  return { found: true, category: exact, file: f, content: readFileSync(join(dir, f), "utf8").slice(0, 20000) };
}

function listFiles(dir: string): string[] {
  try {
    return readdirSync(dir).filter((f) => f.endsWith(".md") || f.endsWith(".txt") || f.endsWith(".yaml")).sort();
  } catch {
    return [];
  }
}

function countTemplates(): number {
  try {
    let n = 0;
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) walk(join(dir, e.name));
        else if (e.name.endsWith(".yaml")) n++;
      }
    };
    walk(TEMPLATES);
    return n;
  } catch {
    return 0;
  }
}

export function templateLookup(topic: string, limit = 10): Record<string, unknown> {
  const key = topic.toLowerCase();
  const hits: Array<{ path: string; name: string; id: string }> = [];
  const walk = (dir: string, depth = 0) => {
    if (depth > 6 || hits.length >= limit * 3) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) walk(join(dir, e.name), depth + 1);
      else if (e.name.endsWith(".yaml")) {
        const name = e.name.toLowerCase();
        if (name.includes(key)) {
          const full = join(dir, e.name);
          let id = "";
          try {
            const content = readFileSync(full, "utf8");
            const m = content.match(/^\s*id:\s*(.+)$/m);
            if (m) id = m[1].trim();
          } catch { /* ignore */ }
          hits.push({ path: full.replace(ROOT + "/", ""), name: e.name, id });
        }
      }
    }
  };
  walk(TEMPLATES);
  return { found: hits.length > 0, topic, count: hits.length, templates: hits.slice(0, limit) };
}

// ---------------------------------------------------------------------------
// Bypass techniques — when a probe is blocked by a defense (WAF/filter/auth/rate-limit).
// ---------------------------------------------------------------------------

interface BypassTechnique {
  id: string;
  name: string;
  how: string;
  example?: string;
}
interface BypassCategory {
  id: string;
  defense: string;
  techniques: BypassTechnique[];
}

const BYPASS_ALIASES: Record<string, string> = {
  "403": "auth", "401": "auth", forbidden: "auth", "auth bypass": "auth", authorization: "auth", acl: "auth", access: "auth",
  waf: "waf", firewall: "waf", modsecurity: "waf", cloudflare: "waf",
  filter: "filter", sanitizer: "filter", blacklist: "filter", whitelist: "filter", validation: "filter", input: "filter",
  "rate limit": "rate_limit", ratelimit: "rate_limit", captcha: "rate_limit", bot: "rate_limit", "bot protection": "rate_limit",
};

export function bypassLookup(defense?: string): Record<string, unknown> {
  const data = loadJson<{ categories: BypassCategory[] }>("bypass_techniques");
  if (!data) return { found: false, error: "bypass_techniques.json not found" };
  const cats = data.categories;
  if (!defense) {
    return {
      found: true,
      categories: cats.map((c) => ({ id: c.id, defense: c.defense, techniques: c.techniques.length })),
    };
  }
  const key = defense.toLowerCase();
  const norm = BYPASS_ALIASES[key] ?? key;
  const match = cats.find(
    (c) => c.id === norm || c.defense.toLowerCase().includes(norm) || norm.includes(c.id),
  );
  if (!match) return { found: false, defense, suggestions: cats.map((c) => c.id) };
  return { found: true, defense: match.defense, techniques: match.techniques };
}

// ---------------------------------------------------------------------------
// Chain-to-chain composition — which escalation chains naturally follow another.
// ---------------------------------------------------------------------------

export function chainLinks(): Record<string, unknown> {
  const data = loadJson<{ links: Array<{ from: string; to: string[]; via: string }> }>("chain_links");
  if (!data) return { found: false, error: "chain_links.json not found" };
  return { found: true, total: data.links.length, links: data.links };
}

// ---------------------------------------------------------------------------
// Retry guidance — structured failure recovery (empty/blocked/sanitized/failed).
// ---------------------------------------------------------------------------

export function retryGuidance(signal?: string): Record<string, unknown> {
  const data = loadJson<{ modes: Array<{ id: string; signal: string; actions: string[] }> }>("retry_guidance");
  if (!data) return { found: false, error: "retry_guidance.json not found" };
  if (!signal) {
    return {
      found: true,
      modes: data.modes.map((m) => ({ id: m.id, signal: m.signal, actions: m.actions.length })),
    };
  }
  const ALIASES: Record<string, string> = {
    empty: "empty_output", "no output": "empty_output", stale: "empty_output",
    blocked: "blocked", waf: "blocked", filter: "blocked", firewall: "blocked",
    sanitized: "sanitized", sanitizer: "sanitized", neutralized: "sanitized",
    subagent: "subagent_failed", "sub-agent": "subagent_failed", delegate: "subagent_failed",
    model: "model_failed", "rate limit": "model_failed", ratelimit: "model_failed", quota: "model_failed", context: "model_failed",
    timeout: "timeout", "timed out": "timeout", slow: "timeout", hang: "timeout",
    unconfirmed: "unconfirmed", "not confirmed": "unconfirmed",
    low: "low_severity", "low severity": "low_severity",
  };
  const key = signal.toLowerCase().trim();
  const norm = ALIASES[key] ?? key.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  const match = data.modes.find(
    (m) => m.id === norm || norm.includes(m.id) || m.id.includes(norm),
  );
  if (!match) return { found: false, signal, suggestions: data.modes.map((m) => m.id) };
  return { found: true, mode: match.id, signal: match.signal, actions: match.actions };
}

// ---------------------------------------------------------------------------
// Orchestration framework — lifecycle + team + handoff + termination.
// ---------------------------------------------------------------------------

export function orchestration(part?: string): Record<string, unknown> {
  const data = loadJson<{
    lifecycle: Array<Record<string, unknown>>;
    team: Array<Record<string, unknown>>;
    handoff: Record<string, unknown>;
    termination: Record<string, unknown>;
  }>("orchestration");
  if (!data) return { found: false, error: "orchestration.json not found" };
  if (!part) {
    return {
      found: true,
      phases: data.lifecycle.map((p) => ({ phase: p.phase, name: p.name })),
      team: data.team.map((r) => ({ id: r.id, name: r.name })),
    };
  }
  const q = part.toLowerCase();
  if (q === "lifecycle" || q === "phases") return { found: true, lifecycle: data.lifecycle };
  if (q === "team" || q === "roles") return { found: true, team: data.team };
  if (q === "handoff") return { found: true, handoff: data.handoff };
  if (q === "termination" || q === "done") return { found: true, termination: data.termination };
  const phase = data.lifecycle.find((p) => String(p.phase) === q);
  if (phase) return { found: true, ...phase };
  const role = data.team.find((r) => String(r.id) === q);
  if (role) return { found: true, ...role };
  return {
    found: false,
    part,
    suggestions: ["lifecycle", "team", "handoff", "termination", ...data.lifecycle.map((p) => String(p.phase)), ...data.team.map((r) => String(r.id))],
  };
}

// ---------------------------------------------------------------------------
// Model fallback — classify a model/sub-agent failure and decide the recovery.
// More mature than "fall back on any error": each class is retryable or not,
// with a per-class action (retry+backoff / fall back / shrink / fix / abort)
// and a fallback chain that forbids downgrading the model.
// ---------------------------------------------------------------------------

export function modelFallback(signal?: string): Record<string, unknown> {
  const data = loadJson<{
    error_classes: Array<{ id: string; signals: string[]; retryable: boolean; backoff: boolean; action: string }>;
    fallback_chain: string[];
    backoff: Record<string, unknown>;
  }>("model_fallback");
  if (!data) return { found: false, error: "model_fallback.json not found" };
  if (!signal) {
    return {
      found: true,
      error_classes: data.error_classes.map((c) => ({ id: c.id, retryable: c.retryable, backoff: c.backoff })),
      fallback_chain: data.fallback_chain,
      backoff: data.backoff,
    };
  }
  const q = signal.toLowerCase();
  for (const c of data.error_classes) {
    if (c.signals.some((s) => q.includes(s.toLowerCase()))) {
      return {
        found: true,
        class: c.id,
        retryable: c.retryable,
        backoff: c.backoff,
        action: c.action,
        fallback_chain: data.fallback_chain,
        backoff_schedule: c.backoff ? data.backoff : null,
      };
    }
  }
  return { found: false, signal, suggestions: data.error_classes.map((c) => c.id) };
}

// ---------------------------------------------------------------------------
// Doctrine map — the interconnected doctrine: phase -> skill -> tools -> data.
// ---------------------------------------------------------------------------

export function doctrineMap(part?: string): Record<string, unknown> {
  const data = loadJson<{
    phases: Array<Record<string, unknown>>;
    cross_cutting: Array<Record<string, unknown>>;
  }>("doctrine_map");
  if (!data) return { found: false, error: "doctrine_map.json not found" };
  if (!part) {
    return {
      found: true,
      phases: data.phases.map((p) => ({ phase: p.phase, skill: p.skill, wstg: p.wstg })),
      cross_cutting: data.cross_cutting,
    };
  }
  const q = part.toLowerCase();
  const phase = data.phases.find((p) => String(p.phase) === q);
  if (phase) return { found: true, ...phase };
  if (q === "cross_cutting" || q === "cross" || q === "moments") {
    return { found: true, cross_cutting: data.cross_cutting };
  }
  return {
    found: false,
    part,
    suggestions: ["cross_cutting", ...data.phases.map((p) => String(p.phase))],
  };
}

// ---------------------------------------------------------------------------
// WSTG map — OWASP category -> Blitz coverage (skill/phase/tools/data).
// ---------------------------------------------------------------------------

export function wstgMap(category?: string): Record<string, unknown> {
  const data = loadJson<{ categories: Array<Record<string, unknown>> }>("wstg_map");
  if (!data) return { found: false, error: "wstg_map.json not found" };
  if (!category) {
    return {
      found: true,
      categories: data.categories.map((c) => ({ wstg: c.wstg, name: c.name, phase: c.phase, skill: c.skill })),
    };
  }
  const q = category.toUpperCase();
  const c = data.categories.find(
    (x) =>
      String(x.wstg).toUpperCase() === q ||
      String(x.name).toLowerCase().includes(category.toLowerCase()) ||
      String(x.wstg).toUpperCase().includes(q),
  );
  if (c) return { found: true, ...c };
  return { found: false, category, suggestions: data.categories.map((x) => String(x.wstg)) };
}

// ---------------------------------------------------------------------------
// Technique base — detailed per-class bug-hunting methodology + tricks.
// ---------------------------------------------------------------------------

export function techniqueLookup(cls?: string): Record<string, unknown> {
  const data = loadJson<{ classes: Array<Record<string, unknown>> }>("techniques");
  if (!data) return { found: false, error: "techniques.json not found" };
  if (!cls) {
    return {
      found: true,
      classes: data.classes.map((c) => ({ id: c.id, name: c.name })),
    };
  }
  const q = cls.toLowerCase();
  const c = data.classes.find(
    (x) =>
      String(x.id).toLowerCase() === q ||
      String(x.id).toLowerCase().includes(q) ||
      String(x.name).toLowerCase().includes(q),
  );
  if (c) return { found: true, ...c };
  return { found: false, cls, suggestions: data.classes.map((x) => String(x.id)) };
}

// ---------------------------------------------------------------------------
// Framework tricks — framework-specific exploitation (signals, vulns, tricks).
// ---------------------------------------------------------------------------

export function frameworkTricks(framework?: string): Record<string, unknown> {
  const data = loadJson<{ frameworks: Array<Record<string, unknown>> }>("framework_tricks");
  if (!data) return { found: false, error: "framework_tricks.json not found" };
  if (!framework) {
    return { found: true, frameworks: data.frameworks.map((f) => ({ framework: f.framework })) };
  }
  const q = framework.toLowerCase();
  const f = data.frameworks.find((x) => String(x.framework).toLowerCase().includes(q));
  if (f) return { found: true, ...f };
  return { found: false, framework, suggestions: data.frameworks.map((x) => String(x.framework)) };
}

// ---------------------------------------------------------------------------
// Resource index — curated domain-specific security resources (Awesome lists).
// ---------------------------------------------------------------------------

export function resourceLookup(category?: string): Record<string, unknown> {
  const data = loadJson<{ resources: Array<Record<string, unknown>> }>("resources");
  if (!data) return { found: false, error: "resources.json not found" };
  if (!category) {
    return {
      found: true,
      resources: data.resources.map((r) => ({ id: r.id, name: r.name, category: r.category, use_when: r.use_when })),
    };
  }
  const q = category.toLowerCase();
  const matches = data.resources.filter(
    (r) =>
      String(r.category).toLowerCase() === q ||
      String(r.id).toLowerCase().includes(q) ||
      String(r.name).toLowerCase().includes(q) ||
      String(r.use_when).toLowerCase().includes(q),
  );
  if (matches.length > 0) return { found: true, matches };
  return { found: false, category, suggestions: [...new Set(data.resources.map((r) => String(r.category)))] };
}

// ---------------------------------------------------------------------------
// Taxonomy — OWASP API Top 10 + CWE mapping (for grounding + reporting).
// ---------------------------------------------------------------------------

export function taxonomy(kind?: string, query?: string): Record<string, unknown> {
  if (kind === "api" || kind === "api_top10" || kind === "owasp-api") {
    const data = loadJson<{ risks: Array<Record<string, unknown>> }>("api_top10");
    if (!data) return { found: false, error: "api_top10.json not found" };
    if (!query) return { found: true, risks: data.risks };
    const q = query.toLowerCase();
    const r = data.risks.find(
      (x) => String(x.id).toLowerCase() === q || String(x.name).toLowerCase().includes(q),
    );
    if (r) return { found: true, ...r };
    return { found: false, query, suggestions: data.risks.map((x) => String(x.id)) };
  }
  if (kind === "cwe" || kind === "weakness") {
    const data = loadJson<{ mapping: Array<Record<string, unknown>> }>("cwe_map");
    if (!data) return { found: false, error: "cwe_map.json not found" };
    if (!query) return { found: true, mapping: data.mapping };
    const q = query.toLowerCase();
    const qNum = q.replace(/^cwe-?/i, "");
    const m = data.mapping.filter(
      (x) => String(x.id).toLowerCase().includes(q) || String(x.cwe).toLowerCase().replace(/^cwe-?/i, "") === qNum || String(x.name).toLowerCase().includes(q),
    );
    if (m.length > 0) return { found: true, matches: m };
    return { found: false, query, suggestions: data.mapping.map((x) => String(x.id)) };
  }
  if (kind === "web" || kind === "owasp" || kind === "top10" || kind === "web_top10") {
    const data = loadJson<{ risks: Array<Record<string, unknown>> }>("owasp_top10");
    if (!data) return { found: false, error: "owasp_top10.json not found" };
    if (!query) return { found: true, risks: data.risks };
    const q = query.toLowerCase();
    const r = data.risks.find(
      (x) => String(x.id).toLowerCase() === q || String(x.name).toLowerCase().includes(q),
    );
    if (r) return { found: true, ...r };
    return { found: false, query, suggestions: data.risks.map((x) => String(x.id)) };
  }
  if (kind === "asvs" || kind === "verification") {
    const data = loadJson<{ chapters: Array<Record<string, unknown>> }>("asvs");
    if (!data) return { found: false, error: "asvs.json not found" };
    if (!query) return { found: true, chapters: data.chapters };
    const q = query.toLowerCase();
    const c = data.chapters.find(
      (x) => String(x.id).toLowerCase() === q || String(x.name).toLowerCase().includes(q),
    );
    if (c) return { found: true, ...c };
    return { found: false, query, suggestions: data.chapters.map((x) => String(x.id)) };
  }
  return {
    found: false,
    error: "unknown taxonomy kind",
    usage: "taxonomy(kind='web'|'api'|'cwe'|'asvs', query?)",
  };
}
