/** Foundry runner — execute a Web3 PoC test to PROVE a finding.
 *
 *  `foundry_poc` generates a template; `foundry_run` actually executes it. Given
 *  a vulnerable contract + a PoC test (or a class to auto-generate from), it
 *  scaffolds a temp Foundry project and runs `forge test`. A PASSING PoC test is
 *  the proof: the exploit reproduces. Deterministic — the verdict is forge's own
 *  test result, never a guess.
 */
import { execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { foundryPoc } from "./web3.js";

function findForge(): string | null {
  try {
    const p = execSync("which forge 2>/dev/null", { encoding: "utf8", timeout: 3000 }).trim();
    if (p) return p;
  } catch {
    /* not on PATH */
  }
  const home = process.env.HOME ?? "/root";
  const candidates = [`${home}/.foundry/bin/forge`, "/usr/local/bin/forge", "/usr/bin/forge"];
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
}

export interface FoundryRunInput {
  contract_code: string;
  poc_code?: string;
  class_?: string; // if poc_code omitted, generate from this class
  contract_name?: string;
  timeout_ms?: number;
}

export interface FoundryTestResult {
  name: string;
  status: "pass" | "fail";
  detail?: string;
}

export interface FoundryRunResult {
  forge: string | null;
  result: "pass" | "fail" | "error";
  verdict: string;
  test_results: FoundryTestResult[];
  output: string;
}

function runForge(forge: string, dir: string, timeoutMs: number): { exit: number; out: string } {
  try {
    const out = execSync(`${forge} test -vv`, { cwd: dir, encoding: "utf8", timeout: timeoutMs, env: { ...process.env } });
    return { exit: 0, out };
  } catch (e: any) {
    return { exit: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

export function parseTestResults(out: string): FoundryTestResult[] {
  const results: FoundryTestResult[] = [];
  for (const line of out.split("\n")) {
    const pass = line.match(/\[PASS\]\s+(\S+)/);
    // forge uses [FAIL], [FAIL: reason], or [FAIL. Reason: ...]
    const fail = line.match(/\[FAIL[^\]]*\]\s+(\S+)/);
    if (pass) results.push({ name: pass[1], status: "pass" });
    else if (fail) results.push({ name: fail[1], status: "fail" });
  }
  return results;
}

export async function foundryRun(input: FoundryRunInput): Promise<FoundryRunResult> {
  const forge = findForge();
  const name = input.contract_name ?? "Vulnerable";
  if (!forge) {
    return {
      forge: null, result: "error",
      verdict: "forge not installed — run: curl -L https://foundry.paradigm.xyz | bash && foundryup",
      test_results: [], output: "forge binary not found on PATH or ~/.foundry/bin",
    };
  }

  const poc = input.poc_code ?? foundryPoc((input.class_ ?? "missing_access_control") as any, name);
  const dir = mkdtempSync(join(tmpdir(), "blitzstrike-foundry-"));
  try {
    // Scaffold via `forge init` (pulls forge-std + remappings), then overwrite
    // the example files with the target contract + PoC.
    try {
      execSync(`${forge} init --force --no-git ${dir}`, { stdio: "ignore", timeout: 60000 });
    } catch {
      /* forge init failed — fall back to a bare scaffold (no forge-std) */
      mkdirSync(join(dir, "src"), { recursive: true });
      mkdirSync(join(dir, "test"), { recursive: true });
      writeFileSync(join(dir, "foundry.toml"), `[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc = "0.8.20"\n`);
    }
    for (const f of ["Counter.sol", "Counter.t.sol", "Counter.s.sol"]) {
      for (const sub of ["src", "test", "script"]) {
        try { rmSync(join(dir, sub, f), { force: true }); } catch { /* ignore */ }
      }
    }
    writeFileSync(join(dir, "src", `${name}.sol`), input.contract_code);
    writeFileSync(join(dir, "test", `${name}.t.sol`), poc);

    const { out } = runForge(forge, dir, input.timeout_ms ?? 60000);
    const tests = parseTestResults(out);
    const anyFail = tests.some((t) => t.status === "fail");
    // A PoC test that PASSES = the exploit reproduced = the finding is PROVEN.
    // No tests ran = compile/setup error. Some test failed = the exploit did not reproduce.
    const result: FoundryRunResult["result"] = tests.length === 0 ? "error" : !anyFail ? "pass" : "fail";
    return {
      forge,
      result,
      verdict:
        result === "pass" ? "PoC test PASSED — the exploit reproduced, the finding is PROVEN"
          : result === "fail" ? "PoC test did not fully pass — the exploit did NOT reproduce cleanly (review the test/fixture)"
          : "forge test errored — the project did not compile/run (see output)",
      test_results: tests,
      output: out.slice(-3000),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
