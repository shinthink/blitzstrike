/** Hackbot Arena — Blitz Strike DETECTION benchmark (internal).
 *
 *  Scans every lab's source with the real Blitz Strike detectors (taint engine,
 *  complex-bug detectors, sink scanner) and emits a per-lab set of detected
 *  vuln-class signals. The evaluator then classifies each signal TP/FP against
 *  the lab's canonical vuln class (from challenge.yml).
 */
import { readFileSync } from "node:fs";
import "../src/adapters.ts";
import { iterSourceFiles, scanFile } from "../src/scanner.ts";
import { detectComplexBugs } from "../src/complex-bugs.ts";
import { runTaintEngine, detectLanguage } from "../src/universal-taint.ts";

const LABS_DIR = "/tmp/hackbot-arena/labs";

const labs = Array.from({ length: 30 }, (_, i) => `labs${String(i + 1).padStart(2, "0")}`);

interface Signal {
  kind: string; // "detector" | "taint" | "sink"
  type: string;
  line?: number;
  file?: string;
  severity?: string;
}

for (const lab of labs) {
  const dir = `${LABS_DIR}/${lab}/challenge`;
  const files = iterSourceFiles(dir, 4000);
  const signals = new Map<string, Signal>(); // dedupe by kind:type

  for (const f of files) {
    let code = "";
    try { code = readFileSync(f, "utf8"); } catch { continue; }
    const rel = f.replace(`${LABS_DIR}/${lab}/`, "");

    const lang = detectLanguage(f);
    if (lang) {
      const t = runTaintEngine(lang, code, f);
      for (const x of t.findings) {
        const key = `taint:${x.sink}`;
        if (!signals.has(key)) signals.set(key, { kind: "taint", type: x.sink, line: x.sink_line, file: rel });
      }
    }

    for (const x of detectComplexBugs(code, f)) {
      const key = `detector:${x.type}`;
      if (!signals.has(key)) signals.set(key, { kind: "detector", type: x.type, line: x.line, file: rel, severity: x.severity });
    }

    for (const s of scanFile(f).sinks) {
      const key = `sink:${s.class}`;
      if (!signals.has(key)) signals.set(key, { kind: "sink", type: s.class, line: s.line, file: rel });
    }
  }

  const sorted = [...signals.values()].sort((a, b) => (a.kind + a.type).localeCompare(b.kind + b.type));
  console.log(JSON.stringify({ lab, files: files.length, signals: sorted.map((s) => ({ ...s, file: s.file ?? undefined })) }));
}
