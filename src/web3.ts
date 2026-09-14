/** Web3 / smart-contract audit — deterministic Solidity detectors.
 *
 *  Blitz Strike's web2 engine (taint + complex-bug detectors) does not cover
 *  EVM/Solidity. This module adds a deterministic, pattern-based Solidity
 *  auditor for the 10 highest-value smart-contract bug classes, plus a Foundry
 *  PoC template generator so a hit turns into an executable proof.
 *
 *  Philosophy: same as web2 — detection is a HYPOTHESIS, a hit must be verified
 *  (here: by running the Foundry PoC). Deterministic patterns, no LLM guessing.
 */

export type Web3Class =
  | "reentrancy"
  | "unchecked_return"
  | "unchecked_arithmetic"
  | "tx_origin_auth"
  | "signature_replay"
  | "unprotected_selfdestruct"
  | "delegatecall_user_input"
  | "missing_access_control"
  | "timestamp_dependence"
  | "oracle_manipulation"
  | "unbounded_loop"
  | "encode_packed_collision"
  | "address_zero_check";

export interface Web3Finding {
  file: string;
  line: number;
  class_: Web3Class;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string;
  evidence: string;
  detail: string;
}

const SEVERITY: Record<Web3Class, { severity: Web3Finding["severity"]; cwe: string; category: string }> = {
  reentrancy: { severity: "critical", cwe: "CWE-841", category: "Reentrancy (state change after external call)" },
  unchecked_return: { severity: "high", cwe: "CWE-252", category: "Unchecked return value of low-level call" },
  unchecked_arithmetic: { severity: "high", cwe: "CWE-190", category: "Unchecked arithmetic (overflow/underflow)" },
  tx_origin_auth: { severity: "high", cwe: "CWE-284", category: "tx.origin authentication (phishing)" },
  signature_replay: { severity: "high", cwe: "CWE-294", category: "Signature replay (no nonce/chainId/deadline)" },
  unprotected_selfdestruct: { severity: "critical", cwe: "CWE-284", category: "Unprotected selfdestruct" },
  delegatecall_user_input: { severity: "critical", cwe: "CWE-284", category: "delegatecall to user-controlled address" },
  missing_access_control: { severity: "high", cwe: "CWE-284", category: "Privileged function missing access control" },
  timestamp_dependence: { severity: "medium", cwe: "CWE-1164", category: "block.timestamp / block.number dependence" },
  oracle_manipulation: { severity: "high", cwe: "CWE-1235", category: "Spot-price oracle (DEX pair) manipulation" },
  unbounded_loop: { severity: "medium", cwe: "CWE-834", category: "Unbounded loop over user-controlled length" },
  encode_packed_collision: { severity: "high", cwe: "CWE-701", category: "abi.encodePacked hash collision (dynamic types)" },
  address_zero_check: { severity: "low", cwe: "CWE-20", category: "Missing address(0) validation on privileged assignment" },
};

function lines(code: string): string[] {
  return code.split("\n");
}
function lineNo(code: string, idx: number): number {
  let n = 1;
  for (let i = 0; i < idx; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

// strip //, /* */ comments (preserve positions)
function stripComments(code: string): string {
  let out = "";
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    const nx = code[i + 1];
    if (c === "/" && nx === "/") {
      while (i < n && code[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && nx === "*") {
      i += 2;
      let closed = false;
      while (i < n) {
        if (code[i] === "*" && code[i + 1] === "/") { i += 2; closed = true; break; }
        if (code[i] === "\n") out += "\n";
        i++;
      }
      if (!closed) break;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

function push(out: Web3Finding[], file: string, code: string, idx: number, cls: Web3Class, evidence: string, detail: string): void {
  const meta = SEVERITY[cls];
  out.push({ file, line: lineNo(code, idx), class_: cls, category: meta.category, severity: meta.severity, cwe: meta.cwe, evidence, detail });
}

/** Extract a function's body by name (heuristic: `function name(...) { ... }`). */
function functionBody(code: string, name: string): string | null {
  const re = new RegExp(`function\\s+${name}\\s*\\([^)]*\\)[^{]*\\{`);
  const m = re.exec(code);
  if (!m) return null;
  const open = code.indexOf("{", m.index);
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") { depth--; if (depth === 0) return code.slice(open, i + 1); }
  }
  return code.slice(open);
}

export function web3Audit(code: string, file: string): Web3Finding[] {
  const out: Web3Finding[] = [];
  const clean = stripComments(code);
  const ls = lines(code);

  // 1. Reentrancy — an external call (.call{value / .call( / .send( / .transfer() /
  //    safeTransferFrom / safeTransfer, which invoke ERC721/ERC1155 callback hooks)
  //    appears BEFORE a state mutation (assignment to a state var) in the same
  //    function. We approximate: find a low-level call, then look ahead within
  //    the enclosing function for a storage assignment after it.
  const callRe = /\.call\{value:|\.call\(|\.send\(|\.transfer\(|safeTransferFrom\s*\(|safeTransfer\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = callRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    // find enclosing function body end
    const bodyEnd = clean.indexOf("\n    }", m.index);
    const tail = clean.slice(m.index, bodyEnd === -1 ? clean.length : bodyEnd);
    // state mutation AFTER the call: an identifier (optionally indexed like
    // `balance[msg.sender]`) followed by =, -=, or +=.
    if (/\b[a-z_][a-z0-9_]*\s*(\[[^\]]*\])?\s*[-+]?=/.test(tail.slice(tail.indexOf(")") + 1))) {
      push(out, file, code, m.index, "reentrancy", (ls[ln - 1] ?? "").trim(), "An external call is followed by a state mutation in the same function — a classic reentrancy window (the callee can re-enter before state is settled). Apply the checks-effects-interactions pattern: update state FIRST, then make the external call; or use a reentrancy guard (OpenZeppelin ReentrancyGuard).");
    }
  }

  // 2. Unchecked return value of .call/.send
  const lowCallRe = /(?:\(bool\s+\w+\s*,\s*\)\s*=\s*)?([\w.\[\]()]+)\.(?:call|send)\s*(?:\{|\(|;)/g;
  while ((m = lowCallRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const line = ls[ln - 1] ?? "";
    if (/\.call\{value:/.test(line)) continue; // covered by reentrancy when state follows
    if (/require\s*\(|if\s*\(/.test(line)) continue; // return value checked
    push(out, file, code, m.index, "unchecked_return", line.trim(), "A low-level `.call`/`.send` return value is not checked — the call can silently fail (e.g. out-of-gas) while execution continues. Check the boolean success and revert on failure.");
  }

  // 3. Unchecked arithmetic block
  const uncheckedRe = /\bunchecked\s*\{/g;
  while ((m = uncheckedRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "unchecked_arithmetic", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "An `unchecked { }` block disables overflow/underflow checks (Solidity ≥0.8) — arithmetic inside can wrap. Verify each operation is provably safe, or remove the block.");
  }

  // 4. tx.origin auth
  const txOriginRe = /\btx\.origin\b/g;
  while ((m = txOriginRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "tx_origin_auth", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "`tx.origin` is used for authorization — it can be a phishing victim's address when called through a malicious intermediary contract. Use `msg.sender` for auth.");
  }

  // 5. Signature replay — ecrecover without nonce/chainId/deadline
  const ecRe = /\becrecover\s*\(/g;
  while ((m = ecRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const scope = clean.slice(Math.max(0, m.index - 600), m.index);
    if (/\bnonce\b/i.test(scope) && (/\bchainId\b|\bblock\.chainid\b/i.test(scope) || /\bdeadline\b/i.test(scope))) continue;
    push(out, file, code, m.index, "signature_replay", (ls[ln - 1] ?? "").trim(), "`ecrecover` validates a signature without binding it to a nonce / chainId / deadline — the same signature can be replayed on another chain or re-submitted. Include a nonce, the chain id, and an expiry in the signed digest.");
  }

  // 6. Unprotected selfdestruct
  const selfRe = /\bselfdestruct\s*\(/g;
  while ((m = selfRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const scope = clean.slice(Math.max(0, m.index - 800), m.index);
    if (/onlyOwner|require\s*\(\s*msg\.sender|Ownable|onlyRole|_checkOwner/.test(scope)) continue;
    push(out, file, code, m.index, "unprotected_selfdestruct", (ls[ln - 1] ?? "").trim(), "`selfdestruct` is reachable without an ownership/role check — an attacker can destroy the contract and force-send its balance. Gate it behind the owner and emit an event.");
  }

  // 7. delegatecall to user-controlled address
  const delRe = /\.delegatecall\s*\(/g;
  while ((m = delRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "delegatecall_user_input", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "`delegatecall` to a user-controlled address executes the target's code in the caller's storage context — arbitrary storage overwrite / selfdestruct. Never delegatecall to an address derived from user input.");
  }

  // 8. Missing access control on privileged functions
  const fnRe = /function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)/g;
  const privileged = /\b(mint|burn|setOwner|transferOwnership|setPrice|setFee|pause|unpause|upgrade|initialize|claim|withdrawAll|drain|rescue)\b/i;
  while ((m = fnRe.exec(clean)) !== null) {
    const name = m[1];
    if (!privileged.test(name)) continue;
    const body = functionBody(code, name);
    if (!body) continue;
    const authRe = /\bonlyOwner\b|\brequire\s*\(\s*msg\.sender|Ownable|onlyRole|_checkOwner|_onlyOwner|\bowner\b\s*==/.test(body) || /\bmodifier\b/.test(body);
    if (authRe) continue;
    push(out, file, code, m.index, "missing_access_control", (ls[lineNo(code, m.index) - 1] ?? "").trim(), `Privileged function \`${name}()\` has no visible access control (onlyOwner / require(msg.sender==owner) / role check) — anyone can call it. Add an ownership/role modifier.`);
  }

  // 9. block.timestamp / block.number dependence
  const tsRe = /\bblock\.(timestamp|number|hash|difficulty|coinbase)\b/g;
  while ((m = tsRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "timestamp_dependence", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "`block.timestamp`/`block.number` is used in critical logic — miners can manipulate it within a range, and it must never be a source of randomness or a payout/auction boundary. Use an oracle (Chainlink VRF) for randomness and tolerate timestamp skew.");
  }

  // 10. Oracle manipulation — DEX spot price (getReserves / slot0 / getAmountOut)
  //     or a stale Chainlink feed (latestRoundData/latestAnswer without a
  //     staleness check on updatedAt).
  const oracleRe = /\bgetReserves\s*\(|\bspotPrice\b|\bgetAmountsOut\s*\(|\bgetAmountOut\s*\(|\bslot0\s*\(|\blatestRoundData\s*\(|\blatestAnswer\s*\(/g;
  while ((m = oracleRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "oracle_manipulation", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "A DEX pair's spot price (`getReserves`/`getAmountOut`) is used as a price oracle — it can be manipulated with a flash loan. Use a time-weighted average price (TWAP) or a Chainlink price feed.");
  }

  // 11. Unbounded loop over a user-controlled array
  const loopRe = /for\s*\([^;]*;[^;]*;\s*[^)]*\)/g;
  while ((m = loopRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const line = ls[ln - 1] ?? "";
    if (!/\.length\b/.test(line)) continue;
    if (/require\s*\([^)]*\.length\s*[<]=?\s*\d+/.test(line)) continue;
    push(out, file, code, m.index, "unbounded_loop", line.trim(), "A loop iterates over a user-controlled array length with no bound — an attacker can grow the array to force an out-of-gas DoS. Cap the iteration or use a pull-based pattern.");
  }

  // 12. abi.encodePacked hash collision — keccak256 over abi.encodePacked with
  //     dynamic types (string/bytes/array). Packed encoding is not injective, so
  //     two distinct inputs can collide (e.g. ["a","bc"] vs ["ab","c"]) — enabling
  //     signature forgery or duplicate hash bypass.
  const packedRe = /keccak256\s*\(\s*abi\.encodePacked\s*\(/g;
  while ((m = packedRe.exec(clean)) !== null) {
    push(out, file, code, m.index, "encode_packed_collision", (ls[lineNo(code, m.index) - 1] ?? "").trim(), "`keccak256(abi.encodePacked(...))` over dynamic types (string/bytes/array) is ambiguous — ['a','bc'] and ['ab','c'] pack identically, enabling hash collisions and signature forgery (CWE-701). Use `abi.encode` (which pads + length-prefixes each argument) for any hash or signature digest.");
  }

  // 13. Missing address(0) validation — a privileged assignment (owner/admin in a
  //     constructor, setOwner, transferOwnership, initialize) accepts an address
  //     parameter without checking `!= address(0)`.
  const zeroCheckRe = /\b(constructor|initialize|setOwner|transferOwnership|setAdmin|setFeeRecipient|setPendingOwner)\s*\(/g;
  const cleanLines = lines(clean);
  while ((m = zeroCheckRe.exec(clean)) !== null) {
    const ln = lineNo(code, m.index);
    const line = ls[ln - 1] ?? "";
    // the function must take an address parameter assigned to a state var
    if (!/\baddress\b/.test(line)) continue;
    const cleanLine = cleanLines[ln - 1] ?? "";
    // skip if the (comment-stripped) code already checks != address(0)
    if (/address\s*\(\s*0\s*\)/.test(cleanLine) || /!=?\s*address\s*\(\s*0\s*\)/.test(cleanLine)) continue;
    push(out, file, code, m.index, "address_zero_check", line.trim(), "An address parameter is assigned in a privileged function (owner/admin) without a `!= address(0)` check — a zero-address owner can permanently lock the contract. Validate the address before assignment.");
  }

  // Dedup by (class, line)
  const seen = new Set<string>();
  return out.filter((f) => {
    const k = `${f.class_}:${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Ranked summary — group + sort by severity (critical > high > medium). */
export function web3Rank(findings: Web3Finding[]): Array<{ class_: Web3Class; count: number; severity: Web3Finding["severity"]; cwe: string }> {
  const order: Record<Web3Finding["severity"], number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const agg = new Map<Web3Class, { count: number; severity: Web3Finding["severity"]; cwe: string }>();
  for (const f of findings) {
    const e = agg.get(f.class_) ?? { count: 0, severity: f.severity, cwe: f.cwe };
    e.count++;
    agg.set(f.class_, e);
  }
  return [...agg.entries()]
    .map(([class_, v]) => ({ class_, ...v }))
    .sort((a, b) => order[a.severity] - order[b.severity] || b.count - a.count);
}

/** Generate a Foundry PoC template for a finding class — an executable test the
 *  agent fills with the contract under test. */
export function foundryPoc(cls: Web3Class, contractName = "Vulnerable"): string {
  const base = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/${contractName}.sol";

contract ${contractName}Poc is Test {
    ${contractName} internal target;
    address internal attacker = address(0xBEEF);
    address internal victim = address(0xCAFE);

    function setUp() public {
        target = new ${contractName}();
        // fund the target / victim as needed
    }
`;
  const exploit: Record<Web3Class, string> = {
    reentrancy: `    function testReentrancy() public {
        // Attacker contract re-enters before state is settled
        ReentrantAttacker a = new ReentrantAttacker(address(target));
        a.attack{value: 1 ether}();
        assertGt(address(a).balance, 1 ether, "attacker drained more than deposited");
    }
}

contract ReentrantAttacker {
    Vulnerable t;
    constructor(address _t) { t = Vulnerable(_t); }
    function attack() external payable {
        t.deposit{value: msg.value}();
        t.withdraw(msg.value);
    }
    receive() external payable {
        if (address(t).balance > 0) t.withdraw(msg.value);
    }
}`,
    unchecked_return: `    function testUncheckedReturn() public {
        // force the low-level call to fail, observe the contract keeps going
        (bool ok, ) = address(target).call{value: 0}(abi.encodeWithSignature("fail()"));
        assertFalse(ok, "call should fail");
    }`,
    unchecked_arithmetic: `    function testUncheckedArithmetic() public {
        uint256 before = target.counter();
        // trigger the wrap that the unchecked block allowed
        target.triggerOverflow();
        // the bug is PRESENT when the value wrapped (became smaller):
        assertLt(target.counter(), before, "unchecked arithmetic wrapped");
    }`,
    tx_origin_auth: `    function testTxOriginAuth() public {
        // a malicious intermediary makes the victim (tx.origin) call the target
        Phisher p = new Phisher(address(target));
        vm.prank(victim, victim);
        p.forward();
    }
}

contract Phisher {
    Vulnerable t;
    constructor(address _t) { t = Vulnerable(_t); }
    function forward() external { t.restricted(); }
}`,
    signature_replay: `    function testSignatureReplay() public {
        // replay the same signature on a second chain / a second time
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPk, digest);
        target.claim(attacker, 1 ether, deadline, v, r, s);
        // the bug is PRESENT when the SAME signature replays (no nonce/chainId binding):
        target.claim(attacker, 1 ether, deadline, v, r, s);
        assertGt(target.balanceOf(attacker), 1 ether, "signature replayed");
    }`,
    unprotected_selfdestruct: `    function testUnprotectedSelfdestruct() public {
        vm.prank(attacker);
        target.kill(); // the bug is PRESENT when a non-owner can destroy it
        assertEq(address(target).code.length, 0, "contract destroyed by non-owner");
    }`,
    delegatecall_user_input: `    function testDelegatecallUserInput() public {
        // attacker supplies a malicious implementation that selfdestructs
        Evil impl = new Evil();
        vm.prank(attacker);
        target.setImplementation(address(impl));
        // the bug is PRESENT when the attacker-supplied implementation actually ran:
        target.exec();
        assertEq(address(target).code.length, 0, "attacker implementation executed");
    }
}

contract Evil {
    function kill() external { selfdestruct(payable(tx.origin)); }
}`,
    missing_access_control: `    function testMissingAccessControl() public {
        vm.prank(attacker);
        target.mint(attacker, 1_000_000 ether); // no owner check
        // the bug is PRESENT when the attacker's mint actually lands:
        assertGt(target.balanceOf(attacker), 0, "attacker minted without auth");
    }`,
    timestamp_dependence: `    function testTimestampDependence() public {
        // warp the timestamp to a favorable value and observe the payout/randomness
        vm.warp(block.timestamp + 1000);
        target.resolve();
        // the bug is PRESENT when the timestamp change altered the outcome:
        assertTrue(/* favorable outcome observed */, "timestamp dependence exploited");
    }`,
    oracle_manipulation: `    function testOracleManipulation() public {
        // swap a large amount to move the spot price, then exploit the target
        pool.swap(attacker, 1_000_000 ether); // move spot price
        target.trade();
        assertGt(target.balanceOf(attacker), 0, "spot-price oracle was manipulated");
    }`,
    unbounded_loop: `    function testUnboundedLoop() public {
        // grow the array past the gas limit to force a DoS
        for (uint i = 0; i < 100_000; i++) target.add(address(uint160(i)));
        vm.expectRevert(); // or assert gas consumption
        target.processAll();
    }`,
    encode_packed_collision: `    function testEncodePackedCollision() public {
        // two distinct inputs pack to the same hash
        bytes32 a = target.hashFor("a", "bc");
        bytes32 b = target.hashFor("ab", "c");
        assertEq(a, b, "abi.encodePacked collision");
    }`,
    address_zero_check: `    function testAddressZeroCheck() public {
        // the bug is PRESENT when the zero address is accepted as owner:
        target.setOwner(address(0));
        assertEq(target.owner(), address(0), "zero address became owner");
    }`,
  };
  return base + (exploit[cls] ?? exploit.missing_access_control) + "\n}\n";
}
