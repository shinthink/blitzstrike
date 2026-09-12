/** SARIF 2.1.0 export (Phase 8 / §32) — CI/CD-friendly findings format.
 *
 * Converts Blitz Strike findings into a SARIF 2.1.0 document consumable by
 * GitHub Code Scanning, GitLab, Azure DevOps, and other SARIF-aware tooling.
 */
import { VERSION } from "./version.js";

export interface SarifFindingInput {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: string;
  file: string;
  line: number;
}

export interface SarifOptions {
  tool?: string;
  uri?: string;
}

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

/** Map a severity label to a SARIF level. */
export function sarifLevel(severity: string): "error" | "warning" | "note" {
  const s = severity.toLowerCase();
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note";
}

/** Build a SARIF 2.1.0 document from normalized findings. */
export function toSarif(findings: SarifFindingInput[], opts: SarifOptions = {}): Record<string, unknown> {
  const tool = opts.tool ?? "Blitz Strike";
  const uri = opts.uri ?? "https://github.com/shinthink/blitzstrike";

  // Unique rule ids -> rules array.
  const ruleIds = [...new Set(findings.map((f) => f.ruleId))];
  const rules = ruleIds.map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
  }));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: f.level,
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: Math.max(1, f.line) },
        },
      },
    ],
  }));

  return {
    version: "2.1.0",
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: tool,
            version: VERSION,
            informationUri: uri,
            rules,
          },
        },
        results,
      },
    ],
  };
}
