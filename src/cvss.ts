/** CVSS v3.1 base score calculator (§38 "CVSS assessment").
 *
 * Deterministic implementation of the FIRST CVSS v3.1 base metrics, so findings
 * can carry a self-computed CVSS score + vector instead of only reading a score
 * from NVD. Severity ratings follow the official CVSS v3.1 bands.
 */

export type CvssMetric = "AV" | "AC" | "PR" | "UI" | "S" | "C" | "I" | "A";

export interface CvssInput {
  AV?: "N" | "A" | "L" | "P";
  AC?: "L" | "H";
  PR?: "N" | "L" | "H";
  UI?: "N" | "R";
  S?: "U" | "C";
  C?: "H" | "L" | "N";
  I?: "H" | "L" | "N";
  A?: "H" | "L" | "N";
}

const AV_WEIGHT: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_WEIGHT: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_WEIGHT: Record<string, Record<string, number>> = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
};
const UI_WEIGHT: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA_WEIGHT: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundup(value: number): number {
  return Math.ceil(value * 10) / 10;
}

/** Compute a CVSS v3.1 base score from metric values (defaults = least severe). */
export function cvssBaseScore(input: CvssInput): number {
  const AV = input.AV ?? "N";
  const AC = input.AC ?? "L";
  const PR = input.PR ?? "N";
  const UI = input.UI ?? "N";
  const S = input.S ?? "U";
  const C = input.C ?? "N";
  const I = input.I ?? "N";
  const A = input.A ?? "N";

  const iscBase = 1 - (1 - CIA_WEIGHT[C]) * (1 - CIA_WEIGHT[I]) * (1 - CIA_WEIGHT[A]);

  let impact: number;
  if (S === "U") {
    impact = 6.42 * iscBase;
  } else {
    impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
  }

  const exploitability = 8.22 * AV_WEIGHT[AV] * AC_WEIGHT[AC] * PR_WEIGHT[S][PR] * UI_WEIGHT[UI];

  if (impact <= 0) return 0;

  if (S === "U") {
    return roundup(Math.min(impact + exploitability, 10));
  }
  return roundup(Math.min(1.08 * (impact + exploitability), 10));
}

/** Build a canonical CVSS v3.1 vector string. */
export function cvssVector(input: CvssInput): string {
  const order: Array<[CvssMetric, string]> = [
    ["AV", input.AV ?? "N"],
    ["AC", input.AC ?? "L"],
    ["PR", input.PR ?? "N"],
    ["UI", input.UI ?? "N"],
    ["S", input.S ?? "U"],
    ["C", input.C ?? "N"],
    ["I", input.I ?? "N"],
    ["A", input.A ?? "N"],
  ];
  return "CVSS:3.1/" + order.map(([k, v]) => `${k}:${v}`).join("/");
}

/** Parse a CVSS v3.1 vector string back into metric values. */
export function parseCvssVector(vector: string): CvssInput | null {
  const m = vector.match(/^CVSS:3\.1\/(.+)$/);
  if (!m) return null;
  const out: CvssInput = {};
  for (const part of m[1].split("/")) {
    const [k, v] = part.split(":");
    if (!k || !v) continue;
    switch (k) {
      case "AV": out.AV = v as CvssInput["AV"]; break;
      case "AC": out.AC = v as CvssInput["AC"]; break;
      case "PR": out.PR = v as CvssInput["PR"]; break;
      case "UI": out.UI = v as CvssInput["UI"]; break;
      case "S": out.S = v as CvssInput["S"]; break;
      case "C": out.C = v as CvssInput["C"]; break;
      case "I": out.I = v as CvssInput["I"]; break;
      case "A": out.A = v as CvssInput["A"]; break;
    }
  }
  return out;
}

export type CvssSeverity = "none" | "low" | "medium" | "high" | "critical";

/** Official CVSS v3.1 qualitative severity bands. */
export function cvssSeverity(score: number): CvssSeverity {
  if (score === 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

/** One-shot: compute score + vector + severity from metric values. */
export function cvssAssess(input: CvssInput): { score: number; vector: string; severity: CvssSeverity } {
  const score = cvssBaseScore(input);
  return { score, vector: cvssVector(input), severity: cvssSeverity(score) };
}
