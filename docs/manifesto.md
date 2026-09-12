# Blitz Strike Manifesto

> A scan hit is a **hypothesis**. A live test is the **verdict**.

Automated security assessment with AI agents has two failure modes that make
most tooling unreliable in practice:

1. **Surface-level pattern matching** — an agent flags every `eval(` or
   `unserialize(` as a vulnerability without establishing *reachability*,
   *authentication bypass*, or *exploitability*.
2. **Unverified reporting** — an agent reports a finding, proof, or exploit that
   was never confirmed live, because producing a confident answer substitutes
   for validation.

Blitz Strike exists to make both impossible.

## The invariants

Every tool, chain, and data layer in Blitz Strike obeys the same rules:

- **A sink is not a vulnerability.** A dangerous function in the same file as
  an unauthenticated handler does not mean the handler calls it. Confirm scope.
- **Every finding carries a refutation path.** A chain step without a
  `negative_control` is a false-positive generator, not a chain.
- **A hypothesis is not a finding.** Nothing is reported until a live test
  reflects a marker AND the negative control stays inert.
- **Data, not code, is the differentiator.** Breadth (tools, skills, manuals, payloads,
  templates) is data. The methodology — refute before report — is what makes
  the data trustworthy.

## Why "universal"

Blitz Strike is a **Model Context Protocol server**, not a plugin for one agent.
The MCP protocol is the harness. One server, every client — Claude Code,
Cursor, Hermes, OpenCode, Gemini, Copilot. No per-client code, no lock-in.

The engagement runs **server-side**: a single `run_engagement` call executes
scope gate → triage → trace → chain enrichment → findings, so every client gets
the same depth regardless of how smart the client model is.

## What we refuse to do

- We do not chase "more files" as a substitute for "better methodology".
- We do not vendor non-permissive data (SUL-1.0 or similar) to inflate breadth.
- We do not report unverified hits. A finding that survived refutation is worth
  more than a hundred surface-level matches.

## The goal

Define the scope. One call. Recon, triage, trace, verification, and a
submission-ready finding — with the exploit-tool manual attached. The human
reviews verdicts, not progress.
