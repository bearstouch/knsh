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
- [x] It is confirmed (or refuted) that an agent CLI with its own sandbox turned off runs correctly inside an envelope
  profile.
- [ ] Denial log entries are read as a non-admin user; latency (p50/p95), duplication and merging behaviour, and the
  exact message format are recorded under C2.
- [x] It is shown whether a custom tag in a deny rule (e.g. `(with message "knsh:<id>")`) survives into the log entry.
- [x] If a claim is refuted, a decision entry or spec change is proposed in
  [../09-reference/decisions.md](../09-reference/decisions.md).

*Spike: Seatbelt limits on process info, signals and Unix sockets (C8)*

- [x] Each rule in the table of [../03-functional-requirements/sandbox-profiles.md](../03-functional-requirements/sandbox-profiles.md)
  has a recorded result: enforceable as specified, enforceable differently, or not enforceable.
- [x] It is shown whether a sandboxed process can read another process's arguments or environment (`ps -E`,
  `sysctl KERN_PROCARGS2`), and whether that can be denied.
- [x] It is shown whether `kill` to a process outside the group can be denied.
- [x] Results recorded under C8; any gap becomes a proposed spec change.

**Exit questions**
*Spike: sandbox nesting and log-based denial reporting (C1, C2)*

- Can the violation reader (KNSH-047) attribute a denial to a session and command by tag alone?
- Which tools must go on the trusted-tools compatibility list (KNSH-076)?

*Spike: Seatbelt limits on process info, signals and Unix sockets (C8)*

- Which SBPL operations and filters does KNSH-045 use for each rule?

**Notes.** Done on macOS 26.6.2 (Apple M1 Pro) with the throwaway harnesses in
[`spikes/knsh-025-seatbelt/`](../../spikes/knsh-025-seatbelt/README.md). The results are under C1, C2 and C8 in
[verification claims](../07-testing/verification-claims.md#seatbelt-results-knsh-025-c1-c2-c8), with proposed
[decisions](../09-reference/decisions.md) 8 to 10, and the changed process-information row in
[sandbox profiles](../03-functional-requirements/sandbox-profiles.md) and FR-SEC-05.

- C1: confirmed for Chromium, Chrome.app, Playwright, `swift build` and Claude Code. Each fails with its own sandbox
  on inside the envelope and works with it off. Claude Code runs correctly inside the envelope with its sandbox off.
- C2: denials are read with `log stream` without root (from an account in `admin`). The tag survives verbatim as the
  last line of the message. Latency p95 is 43 ms; repeats in one process merge into a later "N duplicate reports"
  entry. Signal denials,
  `ENOENT` cases and occasional dropped entries are never reported.
- C8: every rule has a recorded result and an SBPL form. "Own process group" becomes "own sandbox" (decision 8):
  `(target pgrp)` can be escaped with `setpgid`. Hiding other processes' arguments and environment takes two rules;
  macOS 26.6 withholds the environment on its own only for Apple platform binaries (found in review: the first
  harness used `/bin/sleep` as the victim). `kill` outside the sandbox is denied.

**Pending (unchecked boxes):** the first C1 box needs macOS 14 and 15 and Codex CLI (its quarantined 0.165.0 binary
never started, even outside a sandbox). The third box needs a standard (non-admin) account: this one is in `admin`,
although nothing ran as root. Neither is claimed as passed.

**Exit questions.**

- *Can KNSH-047 attribute a denial by tag alone?* For supervised lines, yes, if every tag names the session, the
  command and the rule, and every operation knsh relies on has an explicit tagged deny (decision 9). Inside an
  envelope, only the session can be named. Some denials are never reported.
- *Which tools go on the trusted-tools compatibility list (KNSH-076)?* Chromium and Chrome (`--no-sandbox`),
  Playwright (default `chromiumSandbox: false`), SwiftPM (`--disable-sandbox`), Claude Code (`sandbox.enabled:
  false`) and Codex CLI (`--sandbox danger-full-access`, still to verify). Apps that need LaunchServices (Chrome.app)
  run only as trusted tools. setuid tools (`ps`) cannot run at all (decision 10).
- *Which SBPL operations and filters does KNSH-045 use for each rule?* See the C8 table in verification claims:
  `signal (target same-sandbox)`; `process-info*` with `(target same-sandbox)` plus `sysctl-read`
  `(sysctl-name-prefix "kern.procargs")` and `(sysctl-name-prefix "kern.proc.")`; `network-outbound (remote
  unix-socket (path-literal …))`; `mach-lookup (global-name …)` for LaunchServices, Apple Events, the resolver and
  the control service; and `job-creation`.
