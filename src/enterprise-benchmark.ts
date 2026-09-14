/** Enterprise Benchmark — realistic multi-file, framework-style fixtures.
 *
 * Drives the deterministic detectors DIRECTLY (no Mission Control) against
 * Laravel PHP, Express JS, Django Python, Spring Java, a WordPress batch-route
 * endpoint, and a PHP complex-bug fixture. Reports per-fixture detection +
 * false-positive checks.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { analyzeDataFlow2 } from "./eagle2.js";
import { analyzeTaintUniversal, detectLanguage } from "./universal-taint.js";
import { detectRouteConfusion } from "./route-confusion.js";
import { detectComplexBugs } from "./complex-bugs.js";
import "./adapters.js";

export interface EnterpriseFixture {
  id: string;
  dir: string;
  expected_vulns: number;
}

const ROOT = resolve(process.cwd(), "bench", "enterprise");

export const ENTERPRISE_FIXTURES: EnterpriseFixture[] = [
  { id: "php-laravel", dir: join(ROOT, "php-laravel"), expected_vulns: 4 },
  { id: "js-express", dir: join(ROOT, "js-express"), expected_vulns: 2 },
  { id: "py-django", dir: join(ROOT, "py-django"), expected_vulns: 2 },
  { id: "java-spring", dir: join(ROOT, "java-spring"), expected_vulns: 2 },
  { id: "wp-batch-route", dir: join(ROOT, "wp-batch-route"), expected_vulns: 3 }, // __return_true REST route + missing permission_callback (route confusion) + raw SQLi in get_users
  { id: "php-complex", dir: join(ROOT, "php-complex"), expected_vulns: 4 },
];

export interface EnterpriseResult {
  id: string;
  available: boolean;
  detected: number;
  expected: number;
  recall: number;
}

function sourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(p);
      else if (/\.(php|js|mjs|cjs|py|java)$/i.test(e)) out.push(p);
    }
  };
  walk(root);
  return out;
}

/** Run the deterministic detectors over one fixture and count findings. */
function detectFixture(dir: string): number {
  let count = 0;
  for (const f of sourceFiles(dir)) {
    let code: string;
    try {
      code = readFileSync(f, "utf8");
    } catch {
      continue;
    }
    const lang = detectLanguage(f);
    if (lang?.language === "php" || f.endsWith(".php")) {
      count += analyzeDataFlow2(f).findings.length;
      count += detectRouteConfusion(code, f).length;
      count += detectComplexBugs(code, f).length;
    } else {
      count += analyzeTaintUniversal(code, f).findings.length;
    }
  }
  return count;
}

/** Run the detectors against every enterprise fixture. */
export function runEnterpriseBenchmark(): { fixtures: EnterpriseResult[]; summary: Record<string, number> } {
  const fixtures: EnterpriseResult[] = [];
  for (const fx of ENTERPRISE_FIXTURES) {
    if (!existsSync(fx.dir)) {
      fixtures.push({ id: fx.id, available: false, detected: 0, expected: fx.expected_vulns, recall: 0 });
      continue;
    }
    const detected = detectFixture(fx.dir);
    fixtures.push({
      id: fx.id,
      available: true,
      detected,
      expected: fx.expected_vulns,
      recall: Number((fx.expected_vulns > 0 ? detected / fx.expected_vulns : 0).toFixed(2)),
    });
  }
  const avail = fixtures.filter((f) => f.available);
  const totalDetected = avail.reduce((s, f) => s + f.detected, 0);
  const totalExpected = avail.reduce((s, f) => s + f.expected, 0);
  return {
    fixtures,
    summary: {
      fixtures: avail.length,
      detected_vulns: totalDetected,
      expected_vulns: totalExpected,
      recall: Number((totalExpected > 0 ? totalDetected / totalExpected : 0).toFixed(2)),
    },
  };
}
