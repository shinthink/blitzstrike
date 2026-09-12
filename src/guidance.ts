/** Agent guidance — dynamic next-step directives.
 *
 * Where the MCP `instructions` block gives STATIC workflow guidance (read once
 * at startup), this module gives DYNAMIC guidance: after a tool returns a
 * result, the agent is told exactly what to do next based on what it found.
 *
 * The key principle mirrors the evidence-first model:
 *   scanner hit  ->  trace reachability  ->  verify live  ->  record + report
 *
 * A `next_steps` array is attached to tool outputs so the agent never has to
 * guess the next action after a result.
 */

export interface GuidanceContext {
  tier?: "blitz" | "eagle-eye" | "strike";
  sinkKind?: string;
  findingStatus?: string;
  hasFindings?: boolean;
  sanitizedCount?: number;
  taintedSinks?: string[];
}

const SINK_DIRECTIVES: Record<string, string> = {
  sql_execution:
    "Validate the SQL injection live with strike_verify (use a unique MARKER and a NEGATIVE CONTROL that stays inert), or read_tool_manual for sqlmap. Only a reflected marker + inert control = confirmed.",
  command_execution:
    "Validate command injection with strike_verify (e.g. `id`/`whoami` marker vs a control string). Read the relevant tool manual first (commix / os-command-injection).",
  code_execution:
    "Code execution is a high-impact claim — confirm reachability end-to-end first, then validate with strike_verify. Never report eval/exec without a live marker.",
  file_operations:
    "For upload sinks, confirm the file is writable and the uploaded content is reachable/executable. Read payload_lookup for upload payloads; validate with strike_verify.",
  file_inclusion:
    "Validate LFI/RFI with strike_verify (marker file read vs control). Read payload_lookup for local-file-inclusion payloads and check for wrappers (php://, data://).",
  deserialization:
    "Deserialization needs a crafted gadget chain — read_tool_manual (ysoserial / PHPGGC) and confirm the entry point is reachable before validating.",
  http_request:
    "Validate SSRF with strike_verify (marker to a canary host vs control). Read payload_lookup for ssrf payloads and check for protocol/redirect filters.",
  redirect:
    "Validate open redirect with strike_verify (marker URL vs control). Confirm the redirect reflects attacker-controlled input.",
  html_render:
    "Validate the XSS with strike_verify (reflected marker script vs inert control). Check WAF first with detect_waf — many XSS are filtered at the edge.",
  xml_processing:
    "Validate XXE with strike_verify (external entity marker vs control). Read payload_lookup for xxe payloads.",
  archive_extraction:
    "Validate the archive/path issue (zip-slip / path traversal) with strike_verify. Confirm the extraction path is attacker-controlled.",
  path_traversal:
    "Validate path traversal with strike_verify (marker file read vs control). Read payload_lookup for path-traversal payloads.",
  template_injection:
    "SSTI needs a template-expression probe (e.g. {{7*7}} / ${7*7} / <%= 7*7 %>) — the marker is the evaluated arithmetic, the control is a benign literal. Confirm the template engine actually renders user input before reporting.",
  xpath_injection:
    "Validate XPath injection with strike_verify (an XPath boolean/union probe vs a control that stays inert). Confirm the XPath expression is built from attacker-controlled input.",
  ldap_injection:
    "Validate LDAP injection with strike_verify (an LDAP filter-wildcard/OR probe vs a control). Confirm the filter is concatenated from attacker-controlled input.",
};

export function nextSteps(ctx: GuidanceContext): string[] {
  const steps: string[] = [];

  // 1. If sanitized sinks were observed, note them as NOT findings (no FP).
  if (ctx.sanitizedCount && ctx.sanitizedCount > 0) {
    steps.push(
      `${ctx.sanitizedCount} sink(s) were sanitized and are NOT findings — do not report them. Only tainted, unsanitized, unguarded sinks count.`,
    );
  }

  // 2. Sink-kind directives (EAGLE-EYE tier).
  if (ctx.taintedSinks && ctx.taintedSinks.length > 0) {
    const seen = new Set<string>();
    for (const k of ctx.taintedSinks) {
      if (seen.has(k)) continue;
      seen.add(k);
      const d = SINK_DIRECTIVES[k];
      if (d) steps.push(d);
    }
  }

  // 3. Tier-based fallback.
  if (steps.length === 0 && ctx.hasFindings) {
    steps.push(
      "Findings found. Trace each sink's reachability (taint_file / eagle_eye), then validate live with strike_verify before reporting.",
    );
  }

  // 4. Lifecycle directive (STRIKE / record tier).
  if (ctx.findingStatus) {
    const transitions: Record<string, string> = {
      detected: "detected -> triaged (classify severity + CWE + reachability)",
      triaged: "triaged -> hypothesis (state the sink, source, and expected impact)",
      hypothesis: "hypothesis -> validating (run strike_verify with marker + negative control)",
      validating: "validating -> confirmed (only if marker reflected AND negative control inert) or false_positive",
      confirmed: "confirmed — attach evidence (SHA-256), then report.",
    };
    if (transitions[ctx.findingStatus]) {
      steps.push(`Finding lifecycle next step: ${transitions[ctx.findingStatus]}.`);
    }
  }

  // 5. Always close the loop: record with finding_create + redact secrets.
  if (ctx.hasFindings || ctx.findingStatus) {
    steps.push(
      "Record every confirmed finding with finding_create, attach confidence_score, and redact any secrets before persisting.",
    );
  }

  return steps;
}
