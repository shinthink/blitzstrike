/** Secret taxonomy — the SINGLE source of truth for secret field names, known
 *  secret FORMATS, high-entropy token detection, and redaction patterns. Every
 *  secret-related consumer (sinks.scanSinks, complex-bugs.detectHardcodedSecret,
 *  and the evidence redactor) imports from here so coverage is consistent + DRY.
 *
 *  Detection tiers (precision → recall):
 *   1. FIELD NAME — a known secret field (api_key, db_password, …) assigned a literal.
 *   2. FORMAT      — a known secret format (JWT eyJ…, AWS AKIA…, GitHub ghp_…, …)
 *                    regardless of the variable name. Each format carries a
 *                    severity + category, so a hit is classified, not just flagged.
 *   3. ENTROPY     — a high-entropy token (Shannon ≥ 4 bits/char) in an assignment
 *                    context under a non-obvious name (suspect — verify).
 */

// ---------------------------------------------------------------------------
// Tier 1 — secret field names (the "key" side of a `field = value` assignment)
// ---------------------------------------------------------------------------
export const SECRET_FIELDS =
  "api[_-]?key|apikey|api[_-]?secret|access[_-]?key|access[_-]?token|secret[_-]?key|secret[_-]?access[_-]?key|auth[_-]?token|client[_-]?secret|consumer[_-]?secret|consumer[_-]?key|private[_-]?key|db[_-]?password|database[_-]?password|db[_-]?pass|passwd|password|jwt[_-]?secret|encryption[_-]?key|encryption[_-]?password|github[_-]?token|gitlab[_-]?token|stripe[_-]?key|sendgrid[_-]?api[_-]?key|datadog[_-]?api[_-]?key|cloudflare[_-]?api[_-]?key|slack[_-]?token|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?session[_-]?token|bot[_-]?token";

// ---------------------------------------------------------------------------
// Tier 2 — known secret FORMATS (matched by value shape, not field name).
// Each carries a severity (critical/high/medium/low) + category so a hit is
// classified, not just flagged. Derived from the canonical per-provider token
// shapes; no hardcoded real values.
// ---------------------------------------------------------------------------
export type SecretSeverity = "critical" | "high" | "medium" | "low";

export interface SecretFormat {
  name: string;
  re: RegExp;
  severity: SecretSeverity;
  category: string;
}

export const SECRET_FORMATS: SecretFormat[] = [
  // --- AWS ---
  { name: "AWS access key ID", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical", category: "aws" },
  { name: "AWS session token (temporary)", re: /\bASIA[0-9A-Z]{16}\b/g, severity: "critical", category: "aws" },
  { name: "AWS secret access key", re: /aws[_-]?secret[_-]?access[_-]?key['"\s:=]+([A-Za-z0-9/+=]{40})/gi, severity: "critical", category: "aws" },

  // --- Google Cloud ---
  { name: "GCP service account key", re: /"type"\s*:\s*"service_account"/g, severity: "critical", category: "gcp" },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high", category: "gcp" },

  // --- GitHub ---
  { name: "GitHub PAT (classic)", re: /\bghp_[A-Za-z0-9]{20,}\b/g, severity: "critical", category: "github" },
  { name: "GitHub PAT (fine-grained)", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, severity: "critical", category: "github" },
  { name: "GitHub OAuth token", re: /\bgho_[A-Za-z0-9]{20,}\b/g, severity: "high", category: "github" },
  { name: "GitHub server-to-server token", re: /\bgh[usr]_[A-Za-z0-9]{20,}\b/g, severity: "high", category: "github" },

  // --- Stripe ---
  { name: "Stripe live key", re: /\bsk_live_[0-9A-Za-z]{16,}\b/g, severity: "critical", category: "stripe" },
  { name: "Stripe test key", re: /\bsk_test_[0-9A-Za-z]{16,}\b/g, severity: "low", category: "stripe" },
  { name: "Stripe publishable key", re: /\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b/g, severity: "low", category: "stripe" },

  // --- Slack ---
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: "high", category: "slack" },
  { name: "Slack webhook URL", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: "medium", category: "slack" },

  // --- Email service providers ---
  { name: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, severity: "high", category: "email_svc" },
  { name: "Mailgun API key", re: /\bkey-[0-9a-zA-Z]{32}\b/g, severity: "high", category: "email_svc" },

  // --- Twilio ---
  { name: "Twilio API key", re: /\bSK[0-9a-fA-F]{32}\b/g, severity: "high", category: "twilio" },
  { name: "Twilio account SID", re: /\bAC[0-9a-f]{32}\b/g, severity: "medium", category: "twilio" },
  { name: "Twilio auth token", re: /twilio(.{0,20})?(auth|token)['"=: ]+([a-f0-9]{32})/gi, severity: "high", category: "twilio" },

  // --- PaaS ---
  { name: "Heroku API key", re: /heroku(.{0,20})?api['"=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi, severity: "medium", category: "paas" },

  // --- Firebase ---
  { name: "Firebase URL", re: /\bhttps?:\/\/[a-z0-9-]+\.firebaseio\.com\b/g, severity: "low", category: "firebase" },

  // --- Tokens / auth headers ---
  { name: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, severity: "medium", category: "jwt" },
  { name: "Bearer token", re: /authorization['"=: ]+bearer\s+[A-Za-z0-9._-]{20,}/gi, severity: "medium", category: "bearer" },
  { name: "Basic auth URL", re: /https?:\/\/[^/\s:@]+:[^/\s:@]+@[^/\s]+/g, severity: "medium", category: "basic_auth" },

  // --- Private keys ---
  { name: "RSA private key", re: /-----BEGIN RSA PRIVATE KEY-----/g, severity: "critical", category: "private_key" },
  { name: "EC private key", re: /-----BEGIN EC PRIVATE KEY-----/g, severity: "critical", category: "private_key" },
  { name: "OpenSSH private key", re: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: "critical", category: "private_key" },
  { name: "Generic private key", re: /-----BEGIN (DSA |PGP |)PRIVATE KEY-----/g, severity: "critical", category: "private_key" },

  // --- Generic ---
  { name: "Generic API key / token", re: /(?:api[_-]?key|apikey|api_secret|access_token|secret[_-]?token)['"\s:=]+["']([A-Za-z0-9+/=_-]{24,})["']/gi, severity: "medium", category: "generic" },

  // --- Modern AI APIs ---
  { name: "Anthropic API key", re: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,}\b/g, severity: "critical", category: "ai_api" },
  { name: "OpenAI API key (legacy)", re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, severity: "critical", category: "ai_api" },
  { name: "OpenAI project key", re: /\bsk-proj-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g, severity: "critical", category: "ai_api" },
  { name: "OpenAI session token", re: /\bsess-[A-Za-z0-9]{40}\b/g, severity: "high", category: "ai_api" },
  { name: "Hugging Face token", re: /\bhf_[A-Za-z0-9]{30,}\b/g, severity: "high", category: "ai_api" },

  // --- Cloud infrastructure ---
  { name: "Cloudflare API key", re: /cf[_-]?api[_-]?key['"\s:=]+([a-f0-9]{37})/gi, severity: "critical", category: "infra_api" },
  { name: "DigitalOcean token", re: /\bdop_v1_[a-f0-9]{64}\b/g, severity: "high", category: "infra_api" },

  // --- Package registries ---
  { name: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high", category: "package_registry" },
  { name: "PyPI token", re: /\bpypi-AgENdGV[A-Za-z0-9_-]+\b/g, severity: "high", category: "package_registry" },
  { name: "Docker Hub PAT", re: /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g, severity: "high", category: "package_registry" },

  // --- SaaS ---
  { name: "Atlassian API token", re: /\bATATT3xFfGF0[A-Za-z0-9_-]{20,}\b/g, severity: "high", category: "saas_api" },
  { name: "Linear API key", re: /\blin_api_[A-Za-z0-9]{40}\b/g, severity: "medium", category: "saas_api" },

  // --- Observability ---
  { name: "New Relic license key", re: /\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b/g, severity: "medium", category: "observability" },
  { name: "Datadog API key", re: /dd[_-]?api[_-]?key['"\s:=]+([a-f0-9]{32})/gi, severity: "high", category: "observability" },
  { name: "Sentry DSN", re: /https:\/\/[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io\/[0-9]+/g, severity: "low", category: "observability" },

  // --- Tunneling ---
  { name: "ngrok auth token", re: /\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b/g, severity: "medium", category: "tunneling" },

  // --- Bot tokens ---
  { name: "Discord bot token", re: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g, severity: "high", category: "bot_token" },
  { name: "Telegram bot token", re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, severity: "high", category: "bot_token" },
];

// ---------------------------------------------------------------------------
// Tier 3 — Shannon entropy (catches secrets under non-obvious variable names)
// ---------------------------------------------------------------------------
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

// ---------------------------------------------------------------------------
// Redaction — every self-contained token format above, so redaction always
// covers detection (the key=value formats are already covered by the field-name
// patterns below).
// ---------------------------------------------------------------------------
export const REDACTION_PATTERNS: Array<[RegExp, string]> = [
  // Authorization / bearer tokens
  [/(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._~+/=-]{8,}/gi, "$1$2[REDACTED]"],
  [/(api[_-]?key\s*[:=]\s*)["']?[A-Za-z0-9._-]{16,}["']?/gi, "$1[REDACTED]"],
  [/(access[_-]?token\s*[:=]\s*)["']?[A-Za-z0-9._-]{16,}["']?/gi, "$1[REDACTED]"],
  [/(secret\s*[:=]\s*)["']?[A-Za-z0-9._/-]{16,}["']?/gi, "$1[REDACTED]"],
  [/(password\s*[:=]\s*)["']?[^"'\s,}&]{4,}["']?/gi, "$1[REDACTED]"],
  [/(passwd\s*[:=]\s*)["']?[^"'\s,}&]{4,}["']?/gi, "$1[REDACTED]"],
  [/(private[_-]?key\s*[:=]\s*)["']?[A-Za-z0-9+/=_-]{16,}["']?/gi, "$1[REDACTED]"],
  [/(session\s*[:=]\s*)["']?[A-Za-z0-9._-]{12,}["']?/gi, "$1[REDACTED]"],
  [/(cookie\s*[:=]\s*)["']?[A-Za-z0-9._-]{12,}["']?/gi, "$1[REDACTED]"],
  [/(set-cookie\s*:\s*)[^\r\n]+/gi, "$1[REDACTED]"],
  // Known-format secret tokens (tier 2) — self-contained shapes
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]"],
  [/\bASIA[0-9A-Z]{16}\b/g, "[REDACTED]"],
  [/\bghp_[A-Za-z0-9]{20,}\b/g, "[REDACTED]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "[REDACTED]"],
  [/\bgho_[A-Za-z0-9]{20,}\b/g, "[REDACTED]"],
  [/\bgh[usr]_[A-Za-z0-9]{20,}\b/g, "[REDACTED]"],
  [/\bsk_live_[0-9A-Za-z]{16,}\b/g, "[REDACTED]"],
  [/\bsk_test_[0-9A-Za-z]{16,}\b/g, "[REDACTED]"],
  [/\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b/g, "[REDACTED]"],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED]"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED]"],
  [/\bAC[0-9a-f]{32}\b/g, "[REDACTED]"],
  [/\bSK[0-9a-fA-F]{32}\b/g, "[REDACTED]"],
  [/\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, "[REDACTED]"],
  [/\bkey-[0-9a-zA-Z]{32}\b/g, "[REDACTED]"],
  [/\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED]"],
  [/\bsk-proj-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g, "[REDACTED]"],
  [/\bsess-[A-Za-z0-9]{40}\b/g, "[REDACTED]"],
  [/\bhf_[A-Za-z0-9]{30,}\b/g, "[REDACTED]"],
  [/\bdop_v1_[a-f0-9]{64}\b/g, "[REDACTED]"],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, "[REDACTED]"],
  [/\bpypi-AgENdGV[A-Za-z0-9_-]+\b/g, "[REDACTED]"],
  [/\bdckr_pat_[A-Za-z0-9_-]{27,}\b/g, "[REDACTED]"],
  [/\bATATT3xFfGF0[A-Za-z0-9_-]{20,}\b/g, "[REDACTED]"],
  [/\blin_api_[A-Za-z0-9]{40}\b/g, "[REDACTED]"],
  [/\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b/g, "[REDACTED]"],
  [/\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, "[REDACTED]"],
  [/\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b/g, "[REDACTED]"],
  [/\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g, "[REDACTED]"],
  [/https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g, "[REDACTED]"],
  [/\bhttps?:\/\/[a-z0-9-]+\.firebaseio\.com\b/g, "[REDACTED]"],
  [/https:\/\/[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io\/[0-9]+/g, "[REDACTED]"],
  [/https?:\/\/[^/\s:@]+:[^/\s:@]+@[^/\s]+/g, "[REDACTED]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, "[REDACTED]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED]"],
];

/** Redact secrets from arbitrary text before persistence/report/log/context. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const [re, repl] of REDACTION_PATTERNS) {
    out = out.replace(re, repl);
  }
  return out;
}
