---
name: smart-contract-audit
description: Use when you need to audit Solidity/Vyper smart contracts for reentrancy, access control flaws, integer overflow/underflow, unchecked external calls, price/oracle manipulation, and other known on-chain vulnerability classes before deployment or before moving real funds through a contract.
---

# Smart contract audit

Static analysis + symbolic execution + manual review of known vuln classes. This is not a substitute for a professional third-party audit before mainnet deployment with real value at stake — treat it as the pass you run continuously during development, and before requesting that external audit.

## Prerequisites

- `slither`, `mythril`, `aderyn`, `foundry` (for writing/running PoC tests against findings)

## Workflow

1. **Static analysis with slither** — fast, low false-positive rate on the checks it runs:
   ```bash
   slither . --json findings/slither.json
   ```

2. **Symbolic execution with mythril** for deeper exploit-path detection (slower, run per-contract on anything slither flagged or anything handling value transfer):
   ```bash
   myth analyze contracts/Target.sol -o json > findings/mythril.json
   ```

3. **Cross-check with aderyn** (different analysis engine, catches a different slice of issues):
   ```bash
   aderyn . -o findings/aderyn-report.json
   ```

4. **Manually walk these known vulnerability classes regardless of tool output** — tools miss context-dependent logic bugs:
   - **Reentrancy** — any external call (`.call`, `.transfer` to a contract, token transfer hooks) made before state is updated (checks-effects-interactions violation). Confirm the contract either follows CEI ordering or uses a reentrancy guard.
   - **Access control** — every state-changing function that should be restricted (owner-only, role-gated) actually has the modifier applied; check for functions that look internal/administrative but are `public`/`external` with no guard.
   - **Unchecked external calls** — low-level `.call()` return values not checked, silently continuing execution after a failed transfer.
   - **Integer overflow/underflow** — less critical on Solidity ≥0.8 (built-in checked math) but still relevant in `unchecked{}` blocks or older-version code; confirm arithmetic that should never wrap actually can't.
   - **Oracle/price manipulation** — any function relying on a spot price (especially from a single DEX pool) instead of a time-weighted or multi-source oracle is manipulable within a single transaction via flash loan.
   - **Front-running/MEV exposure** — state-changing functions where transaction ordering affects outcome (e.g., naive AMM swaps without slippage protection, auctions without commit-reveal).
   - **Signature replay** — signed messages/permits without a nonce or chain ID binding, allowing reuse across calls or across chains.
   - **Upgradeable proxy risks** — storage layout collisions between implementation versions, missing access control on the upgrade function itself, uninitialized implementation contracts.

5. **Write a PoC in Foundry for every finding you're not 100% certain about** — a failing/passing test that demonstrates the exploit is far stronger evidence than a static-analysis flag, and gives the developer something concrete to fix against:
   ```bash
   forge test --match-test testExploit_ReentrancyDrainsVault -vvvv
   ```

## Output

`findings/slither.json`, `findings/mythril.json`, `findings/aderyn-report.json`, plus any Foundry PoC test files under `findings/poc/`. Report per finding: contract:function, vulnerability class (SWC-ID where applicable), a PoC or clear exploit narrative, severity, fix.

## Notes

- Tool output on Solidity is noisier than most other languages' static analyzers — expect to manually dismiss a meaningful fraction of slither/mythril output as non-issues (intentional design, already-mitigated pattern) and say so explicitly rather than reporting raw counts.
- Before any mainnet deployment handling real user funds, this pass should be treated as preparation for — not a replacement for — a paid third-party audit and a public bug bounty window.
