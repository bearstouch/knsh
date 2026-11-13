# KNSH-025 — Spike: Seatbelt behaviour (C1, C2, C8)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Spikes | XL (8) | — | none (throwaway prototypes), none | C1, C2, decision 1, FR-SBX-08, FR-AGT-05, C8, FR-SBX-02, FR-SBX-05, FR-SEC-05, NFR-SEC-01 |

**Description.** Merged from *Spike: sandbox nesting and log-based denial reporting (C1, C2)* and *Spike: Seatbelt limits on process info, signals and Unix sockets (C8)*: they are done and validated together because all three claims are Seatbelt behaviour measured on the same test machine.

*Spike: sandbox nesting and log-based denial reporting (C1, C2).* As the engine team, I want to confirm how Seatbelt behaves when nested and how denials appear in
the unified log, so that the envelope design and the violation reader rest on observed facts. Scope: run Chromium,
Playwright, `swift build`, Claude Code and Codex CLI inside a hand-written `sandbox-exec -f` profile on macOS 14, 15
and current; stream denials with `log stream` filtered by a knsh tag as a non-admin user. Out of scope: production
code, profile compiler.

*Spike: Seatbelt limits on process info, signals and Unix sockets (C8).* As the engine team, I want one test per profile rule the spec relies on, so that the Seatbelt compiler
emits rules that actually hold. Scope: process information and signals limited to the own process group; Unix socket
connections limited to a named path (`agent.sock`) and denied for others (`user.sock`, Docker, SSH agent); system
service denials (LaunchServices, Apple Events, launchd job submission, DNS resolver, named Mach service lookup).

**Acceptance criteria**
*Spike: sandbox nesting and log-based denial reporting (C1, C2)*

- [ ] For each listed tool and macOS version, the result (works / fails / how it fails) is recorded in
  [../07-testing/verification-claims.md](../07-testing/verification-claims.md) under C1.
- [ ] It is confirmed (or refuted) that an agent CLI with its own sandbox turned off runs correctly inside an envelope
  profile.
- [ ] Denial log entries are read as a non-admin user; latency (p50/p95), duplication and merging behaviour, and the
  exact message format are recorded under C2.
- [ ] It is shown whether a custom tag in a deny rule (e.g. `(with message "knsh:<id>")`) survives into the log entry.
- [ ] If a claim is refuted, a decision entry or spec change is proposed in
  [../09-reference/decisions.md](../09-reference/decisions.md).

*Spike: Seatbelt limits on process info, signals and Unix sockets (C8)*

- [ ] Each rule in the table of [../03-functional-requirements/sandbox-profiles.md](../03-functional-requirements/sandbox-profiles.md)
  has a recorded result: enforceable as specified, enforceable differently, or not enforceable.
- [ ] It is shown whether a sandboxed process can read another process's arguments or environment (`ps -E`,
  `sysctl KERN_PROCARGS2`), and whether that can be denied.
- [ ] It is shown whether `kill` to a process outside the group can be denied.
- [ ] Results recorded under C8; any gap becomes a proposed spec change.

**Exit questions**
*Spike: sandbox nesting and log-based denial reporting (C1, C2)*

- Can the violation reader (KNSH-047) attribute a denial to a session and command by tag alone?
- Which tools must go on the trusted-tools compatibility list (KNSH-076)?

*Spike: Seatbelt limits on process info, signals and Unix sockets (C8)*

- Which SBPL operations and filters does KNSH-045 use for each rule?
