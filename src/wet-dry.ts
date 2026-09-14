/** WET/DRY traceability — audit the raw→parsed pipeline for report/PoC enrichment.
 *
 *  When the agent enriches a finding (LLM-generated PoC / severity / impact),
 *  the RAW response (WET) and the PARSED result (DRY) are saved separately so a
 *  bad deliverable can be attributed to the right layer:
 *
 *    - WET broken (empty/garbage)  → model / prompt / timeout problem
 *    - WET OK but DRY broken       → parser problem (regex / malformed JSON)
 *    - DRY OK but report bad       → template problem
 *
 *  This is the deterministic version of the self-heal "Enrich" loop: diagnose
 *  WHERE the pipeline broke before re-running it.
 */
export interface WetDryTrace {
  type: string;
  wet: string;
  dry: string;
  wet_ok: boolean;
  dry_ok: boolean;
  diagnosis: string;
  sha256_wet: string;
  sha256_dry: string;
}

function sha256(text: string): string {
  // small local hash to avoid a dependency import cycle
  let h = 5381;
  for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) >>> 0;
  return `djb2-${h.toString(16).padStart(8, "0")}`;
}

export function wetDryTrace(type: string, wet: string, dry: string, dryOk = true): WetDryTrace {
  const wetOk = wet.trim().length > 0;
  const diagnosis = !wetOk
    ? "WET broken — raw output empty/garbage (model, prompt, or timeout problem). Fix the model/prompt, not the parser."
    : !dryOk
      ? "DRY broken — raw OK but parse failed (regex/JSON-malformed). Fix the parser, not the model."
      : "OK — raw and parsed both present. If the report is still bad, the template is the problem.";
  return {
    type,
    wet: wet.trim(),
    dry: dry.trim(),
    wet_ok: wetOk,
    dry_ok: dryOk,
    diagnosis,
    sha256_wet: sha256(wet),
    sha256_dry: sha256(dry),
  };
}
