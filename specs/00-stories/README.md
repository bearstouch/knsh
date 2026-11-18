# Implementation stories

Stories that implement the Kinetic Shell specification, grouped by phase. The phases follow the roadmap
([../01-overview/roadmap.md](../01-overview/roadmap.md)), with a **phase 0** for the foundations every phase needs.
The specification stays the contract: a story implements requirements; it never redefines them.

## Phases

| Phase | Stories | Points | Critical path (points) |
| --- | --- | --- | --- |
| [Phase 0 — Foundations](#phase-0--foundations) | 10 | 44 | 21 |
| [Phase 1 — Observe (advisory)](#phase-1--observe-advisory) | 14 | 72 | 37 |
| [Phase 2 — Contain and decide](#phase-2--contain-and-decide) | 52 | 268 | 57 |
| [Phase 3 — Reverse and protect](#phase-3--reverse-and-protect) | 19 | 98 | 52 |
| [Phase 4 — Native interpreter](#phase-4--native-interpreter) | 14 | 78 | 34 |
| [Phase 5 — Linux](#phase-5--linux) | 10 | 49 | 21 |
| [Phase 6 — Later (unsized backlog)](#phase-6--later-unsized-backlog) | 6 | unsized | — |
| **Total (0–5)** | **119** | **609** | |

Every story is one file, `KNSH-<id>-<slug>.md`, in this folder. This README is the only index: phase goals and
gates, the plan (waves and critical path) and the story index are below.

## Conventions

### Story IDs

`KNSH-NNN`: one incremental sequence across all phases, in planned order (`KNSH-001`, `KNSH-001`, …). The number
carries no phase; the phase is in each story's header table and in the index. IDs are stable and never reused: a
new story takes the next free number, and a split story keeps its ID for the first part while the new parts get
suffixes (`KNSH-050a`, `KNSH-050b`). Reference story IDs in commits and PRs, next to
requirement IDs.

### Sizes

| Size | Points | Rough effort | Rule |
| --- | --- | --- | --- |
| XS | 1 | ≤ ½ day | |
| S | 2 | ~1 day | |
| M | 3 | 2–3 days | |
| L | 5 | ~1 week | |
| XL | 8 | ~2 weeks | Split before starting if a clean seam exists |

Nothing is larger than XL. **Spikes** are time-boxed to their size and end in a written result (an update to
[../07-testing/verification-claims.md](../07-testing/verification-claims.md) or
[../09-reference/decisions.md](../09-reference/decisions.md)), not production code.

### Story template

One file per story: `KNSH-<id>-<slug>.md` in this folder. A new story also gets a row in the story index
below and, if it changes the plan, in its phase's wave table.


```markdown
# KNSH-NNN — Title

[Phase N](README.md#phase-n--name) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | KNSH-028 | `knsh-bash` | FR-LC-02, decision 6 |

**Description.** As a <role>, I want <capability>, so that <outcome>. Then the context and scope a developer
needs, including what is explicitly out of scope.

**Acceptance criteria**
- [ ] Observable, testable statement (Given/When/Then where it helps).

**Unit tests**
- `behaviour_named_test` — what it proves (requirement ID).

**Integration tests** (when the story crosses a process or OS boundary)
- …

**Notes** (optional) — risks, open questions, spec gaps to resolve.
```

### Definition of done (every story)

- Acceptance criteria observed, not assumed (honesty rules in `CLAUDE.md`). Checks that cannot run here are
  recorded as **pending**.
- Unit tests listed in the story exist and pass; failure paths are tested (deny on error, state kept on error).
- Inline docs: crate/module `//!` headers cite spec pages and requirement IDs; every public item has `///` docs.
- `cargo fmt --check`, `clippy -D warnings`, `cargo build --offline --locked`, `cargo doc` with `-D warnings`,
  and `cargo test` are clean.
- No new runtime dependency (or a justified, reviewed, pinned and vendored one).
- Independent review agent pass done; spec pages updated if behaviour or limits changed.

## Phase gates

| Gate | Condition |
| --- | --- |
| Start phase 1 | Phase 0 done |
| Phase 1 release | Labelled **advisory**: no security guarantees, not for unattended agents |
| Start phase 2 build-out | Spikes KNSH-025 – KNSH-027 done and claims C1, C2, C5–C10 resolved |
| Phase 2 release (first release safe for agents) | Parser exit criterion met (KNSH-034), threat-model suite green (KNSH-075), performance targets met (KNSH-076) |
| Start phase 3 checkpoint build-out (KNSH-078 onwards, except KNSH-083) | Spike KNSH-077 done (claims C3, C4); secrets, redaction and irreversible stories may start earlier |
| Phase 4 release | 99% corpus and bash conformance gate (KNSH-109) |
| Phase 5 start | macOS engine stable (phases 2–3 released) |

## Plan

Phases run in order and each starts after the previous phase's gate (above). Inside a phase, stories run in
**waves**: a wave holds every story whose dependencies are all in earlier waves or earlier phases, so a wave's
stories can run in parallel. The **critical path** is the longest chain of dependent stories by points; it sets
the phase's minimum duration whatever the team size. Spikes sit in wave 1 and gate the build-out.

### Phase 0 — Foundations

Phase 0 builds what every later phase stands on: the Cargo workspace and its quality gates, the core value types,
the hand-written parsers for untrusted input (strict JSON, frames, the TOML subset), the platform interface with
deterministic fakes, the JSON-RPC envelope and the SQLite binding. Nothing here is user-visible. **Gate:** phase 1
starts when all phase 0 stories are done and CI is green.

Critical path: [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) → [KNSH-003](KNSH-003-strict-json-reader-and-writer.md) → [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md) → [KNSH-008](KNSH-008-json-rpc-envelope-and-error-codes.md) (**21 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | 5 |
| 2 | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md), [KNSH-003](KNSH-003-strict-json-reader-and-writer.md), [KNSH-006](KNSH-006-toml-subset-parser.md), [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md) | 19 |
| 3 | [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md), [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | 10 |
| 4 | [KNSH-005](KNSH-005-fuzzing-harness.md), [KNSH-008](KNSH-008-json-rpc-envelope-and-error-codes.md), [KNSH-010](KNSH-010-sqlite-ffi-binding.md) | 10 |

### Phase 1 — Observe (advisory)

Phase 1 delivers `knshd` as a launchd user agent with `user.sock`, the record store, the event bus, integration mode
for human zsh and bash with opt-in telemetry, and the first CLI commands. It decides nothing and enforces nothing.
**Gate:** the release is labelled **advisory** — no security guarantees, not for running agents unattended
([roadmap](../01-overview/roadmap.md)). Phase 2 build-out starts after the phase 2 spikes resolve their claims.

Critical path: [KNSH-012](KNSH-012-launchd-user-agent-and-socket-activation.md) → [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md) → [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md) → [KNSH-018](KNSH-018-event-bus-and-subscriptions.md) → [KNSH-023](KNSH-023-cli-knsh-history-and-knsh-events.md) → [KNSH-017](KNSH-017-record-retention-and-forget.md) (**37 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md), [KNSH-012](KNSH-012-launchd-user-agent-and-socket-activation.md), [KNSH-015](KNSH-015-session-model-and-registry.md), [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | 15 |
| 2 | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-020](KNSH-020-integration-mode-hosting-stock-bash.md), [KNSH-022](KNSH-022-osc-7-osc-133-and-login-shell-support.md) | 18 |
| 3 | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md) | 8 |
| 4 | [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-018](KNSH-018-event-bus-and-subscriptions.md) | 16 |
| 5 | [KNSH-021](KNSH-021-human-telemetry-recording-indicator-and-idle-event.md), [KNSH-023](KNSH-023-cli-knsh-history-and-knsh-events.md) | 8 |
| 6 | [KNSH-017](KNSH-017-record-retention-and-forget.md), [KNSH-024](KNSH-024-phase-1-qualification-start-up-benchmark-and-advisory.md) | 7 |

### Phase 2 — Contain and decide

#### Part a: spikes, parser, classifier, policy, sandbox

Phase 2 delivers the first release that is safe to give to agents: envelopes, the supervisor, `knsh-exec`,
deny-by-default profiles, the proxy, `agent.sock`, the authority, signed policy, approvals and standalone rules
([../01-overview/roadmap.md](../01-overview/roadmap.md)). **Part a** covers the platform spikes, the bash
parser and classifier, the policy engine, the Seatbelt compiler and the `knsh-exec` trampoline. Part b (below) builds the supervisor, envelopes,
proxy, hooks and authority on top of it.

**Spike gate:** KNSH-025 – KNSH-027 run first and resolve claims C1, C2 and C5 – C10 in
[../07-testing/verification-claims.md](../07-testing/verification-claims.md). Stories that depend on a spike do not
start until its written result is merged. Parser and policy stories (pure code) may start in parallel with the spikes.

#### Part b: supervisor, envelopes, proxy, hooks, authority

Second half of phase 2: the stories that turn the parser, policy and sandbox from
part a into a running system. That means the
supervisor and its lifecycle, `agent.sock` and the in-envelope client, envelopes and presets, the network proxy,
hooks, the authority over XPC, Touch ID approvals, and the qualification work that gates the release.

Phase 2 is the **first release that is safe to give to agents**. It ships only when all three hold:

1. The parser exit criterion is met (KNSH-034): at least 95% of corpus lines parsed exactly, and every
   accept or reject verdict matches bash.
2. The threat-model end-to-end suite is green (KNSH-075).
3. The phase 2 performance targets are met (KNSH-076).

Conventions, sizes and the definition of done are in [README.md](README.md).

Critical path: [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md) → [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) → [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) → [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md) → [KNSH-040](KNSH-040-rule-matching-and-precedence.md) → [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md) → [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) → [KNSH-052](KNSH-052-agent-execution-records.md) → [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md) → [KNSH-058](KNSH-058-agent-cli-presets-claude-code-codex-cli-generic.md) → [KNSH-076](KNSH-076-phase-2-qualification-performance-and-tool-compatibility.md) (**57 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md), [KNSH-027](KNSH-027-spike-per-command-proxy-credentials-and-tls-server-names.md), [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md), [KNSH-033](KNSH-033-agent-command-corpus-pipeline.md), [KNSH-039](KNSH-039-policy-profile-model-and-loader.md), [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md), [KNSH-056](KNSH-056-knsh-agent-and-session-start-agent.md) | 42 |
| 2 | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md), [KNSH-044](KNSH-044-seatbelt-compiler-file-rules-and-fixed-denies.md), [KNSH-049](KNSH-049-agent-client-knsh-c-forwarding-descriptor-passing-and-shims.md), [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md), [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md) | 39 |
| 3 | [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md), [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md), [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md), [KNSH-061](KNSH-061-tls-server-name-check.md), [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | 36 |
| 4 | [KNSH-032](KNSH-032-parser-limits-and-dynamic-fallback.md), [KNSH-036](KNSH-036-wrapper-unwrapping-and-dynamic-code-classification.md), [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md), [KNSH-038](KNSH-038-line-re-serialisation-with-resolved-absolute-paths.md), [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-047](KNSH-047-sandbox-violation-reader.md) | 34 |
| 5 | [KNSH-034](KNSH-034-differential-parser-tests-against-bash-phase-2-exit.md), [KNSH-040](KNSH-040-rule-matching-and-precedence.md), [KNSH-057](KNSH-057-envelope-profile-and-launch.md) | 15 |
| 6 | [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md), [KNSH-042](KNSH-042-grants.md) | 8 |
| 7 | [KNSH-043](KNSH-043-policy-check-dry-run.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-073](KNSH-073-policy-grant-on-user-sock-with-touch-id.md) | 12 |
| 8 | [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md), [KNSH-052](KNSH-052-agent-execution-records.md), [KNSH-055](KNSH-055-rate-limiting-of-repeated-denials.md), [KNSH-062](KNSH-062-hook-configuration-and-runner.md), [KNSH-066](KNSH-066-local-approvals-approval-knsh-approvals-knsh-approve.md), [KNSH-069](KNSH-069-decision-protocol.md) | 26 |
| 9 | [KNSH-053](KNSH-053-output-capture-command-output-and-exec-with-output-modes.md), [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md) | 24 |
| 10 | [KNSH-058](KNSH-058-agent-cli-presets-claude-code-codex-cli-generic.md), [KNSH-070](KNSH-070-rewrites.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md), [KNSH-075](KNSH-075-threat-model-end-to-end-suite.md) | 21 |
| 11 | [KNSH-072](KNSH-072-pushed-policy-expiry-and-knsh-profile-use.md), [KNSH-074](KNSH-074-fail-closed-operation-and-state-across-restarts.md), [KNSH-076](KNSH-076-phase-2-qualification-performance-and-tool-compatibility.md) | 11 |

### Phase 3 — Reverse and protect

Phase 3 makes agent file changes reversible where that is safe, protects credentials, and flags actions that
checkpoints cannot undo: checkpoints with undo and redo, secrets, and irreversible-action flags
([../01-overview/roadmap.md](../01-overview/roadmap.md)).

**Gate:** the build-out (KNSH-078 onwards, except KNSH-083 and KNSH-089 – KNSH-093, which do not depend on the
spikes) starts only after spikes KNSH-077 have resolved claims C3 and C4 in
[../07-testing/verification-claims.md](../07-testing/verification-claims.md). If a claim fails, the affected
checkpoint stories are re-planned before work starts.

Main spec pages: [checkpoints](../03-functional-requirements/checkpoints.md),
[secrets](../03-functional-requirements/secrets.md),
[irreversible actions](../03-functional-requirements/irreversible-actions.md),
[checkpoint model](../05-models/checkpoint.md), [secret model](../05-models/secret.md).

Critical path: [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md) → [KNSH-078](KNSH-078-apfs-platform-services-and-checkpoint-storage-layout.md) → [KNSH-079](KNSH-079-shadow-builder.md) → [KNSH-080](KNSH-080-file-event-watcher-and-rescans.md) → [KNSH-081](KNSH-081-change-attribution.md) → [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) → [KNSH-084](KNSH-084-undo-and-redo.md) → [KNSH-093](KNSH-093-irreversible-actions-classification-post-run-marking.md) (**52 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md), [KNSH-083](KNSH-083-history-tree.md), [KNSH-089](KNSH-089-secret-stores-keychain-and-authority-supplied-secrets.md), [KNSH-090](KNSH-090-redaction-engine.md), [KNSH-094](KNSH-094-endpoint-security-descendant-client-macos-27-entitlement.md) | 29 |
| 2 | [KNSH-078](KNSH-078-apfs-platform-services-and-checkpoint-storage-layout.md), [KNSH-091](KNSH-091-redaction-on-every-output-path.md) | 11 |
| 3 | [KNSH-079](KNSH-079-shadow-builder.md), [KNSH-092](KNSH-092-secret-injection-and-network-narrowing.md) | 10 |
| 4 | [KNSH-080](KNSH-080-file-event-watcher-and-rescans.md) | 5 |
| 5 | [KNSH-081](KNSH-081-change-attribution.md) | 5 |
| 6 | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) | 5 |
| 7 | [KNSH-084](KNSH-084-undo-and-redo.md), [KNSH-087](KNSH-087-exclusions-retention-and-sensitive-files.md) | 11 |
| 8 | [KNSH-085](KNSH-085-possibly-torn-detection.md), [KNSH-086](KNSH-086-checkpoint-restore-and-checkpoint-diff.md), [KNSH-093](KNSH-093-irreversible-actions-classification-post-run-marking.md), [KNSH-095](KNSH-095-phase-3-performance-qualification.md) | 19 |
| 9 | [KNSH-088](KNSH-088-checkpoint-api-and-cli.md) | 3 |

### Phase 4 — Native interpreter

**Goal.** Replace "one stock interpreter per line" with `knsh`'s own bash-compatible interpreter, so the supervisor
can decide on **every simple command**, including inside scripts and functions
([../04-non-functional-requirements/compatibility.md](../04-non-functional-requirements/compatibility.md),
[../01-overview/roadmap.md](../01-overview/roadmap.md)).

**Target.** Bash 5.2, including bash's POSIX mode when started as `sh` or with `--posix`; at least 99% of the
agent-command corpus behaving as in bash (NFR-COMPAT-02, NFR-COMPAT-11). zsh is never emulated (NFR-COMPAT-03).

**Gate.** Phase 4 ships only when KNSH-109 is green. Until then, integration mode and stock-interpreter agent lines
(phase 2) stay the default; a feature that breaks bash compatibility is not shipped as a default.

**Crate.** The specs do not name the interpreter's crate. Proposal: a new library crate `knsh-interp` that depends on
`knsh-bash` (AST) and `knsh-platform` (process, fd and signal effects), used by the `knsh` binary.
`CLAUDE.md`'s workspace table must be updated when KNSH-096 starts.

Critical path: [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) → [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) → [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md) → [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md) → [KNSH-106](KNSH-106-posix-mode.md) → [KNSH-109](KNSH-109-conformance-gate-bash-test-suite-oils-subset-99-corpus.md) (**34 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | 8 |
| 2 | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md), [KNSH-108](KNSH-108-per-simple-command-decisions.md) | 18 |
| 3 | [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md), [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md), [KNSH-101](KNSH-101-core-builtins.md), [KNSH-103](KNSH-103-functions-scopes-and-arrays.md) | 23 |
| 4 | [KNSH-102](KNSH-102-builtins-test-printf-read.md), [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md), [KNSH-105](KNSH-105-process-substitution-coproc-and-here-documents.md), [KNSH-107](KNSH-107-interactive-line-editor-and-history.md) | 21 |
| 5 | [KNSH-106](KNSH-106-posix-mode.md) | 3 |
| 6 | [KNSH-109](KNSH-109-conformance-gate-bash-test-suite-oils-subset-99-corpus.md) | 5 |

### Phase 5 — Linux

**Goal.** Run the same engine on Linux: the API, records, events, policy format and checkpoint rules stay identical;
only the backends behind the `knsh-platform` interface differ, and `hello` reports which are active
([../02-architecture/platform-support.md](../02-architecture/platform-support.md)).

**Gate.** Phase 5 starts once the macOS engine is stable (phases 2 and 3 released). It ships when KNSH-119 is green.
The dependency policy applies unchanged: replacements for CommonCrypto and the Keychain follow the same rules
(NFR-SUP-07).

Critical path: [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) → [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md) → [KNSH-114](KNSH-114-network-confinement-seccomp-or-network-namespace.md) → [KNSH-119](KNSH-119-linux-qualification.md) (**21 points**).

| Wave | Stories (parallel) | Points |
| --- | --- | --- |
| 1 | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | 3 |
| 2 | [KNSH-111](KNSH-111-in-house-sha-256-and-hmac-replacing-commoncrypto.md), [KNSH-112](KNSH-112-systemd-units-socket-activation-and-control-channel-with-so.md), [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md), [KNSH-115](KNSH-115-inotify-fanotify-watcher-and-reflink-checkpoints.md), [KNSH-116](KNSH-116-secret-service-backend.md), [KNSH-117](KNSH-117-journald-logging-and-violation-reading.md), [KNSH-118](KNSH-118-spike-user-presence-check-for-approvals-on-linux.md) | 36 |
| 3 | [KNSH-114](KNSH-114-network-confinement-seccomp-or-network-namespace.md) | 5 |
| 4 | [KNSH-119](KNSH-119-linux-qualification.md) | 5 |

## Story index

### Phase 0 — Foundations

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Workspace, toolchain, lint baseline and CI | Foundations | L (5) | — | Not started |
| [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | Core value types: ULIDs, canonical paths, redacted text, timestamps | Foundations | M (3) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-003](KNSH-003-strict-json-reader-and-writer.md) | Strict JSON reader and writer | Wire protocol | XL (8) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md) | Frame codec and binary streams | Wire protocol | L (5) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md) | Not started |
| [KNSH-005](KNSH-005-fuzzing-harness.md) | Fuzzing harness | Foundations | S (2) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md), [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md), [KNSH-006](KNSH-006-toml-subset-parser.md) | Not started |
| [KNSH-006](KNSH-006-toml-subset-parser.md) | TOML subset parser | Configuration | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | Platform interface and test fakes | Platform | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md), [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | Not started |
| [KNSH-008](KNSH-008-json-rpc-envelope-and-error-codes.md) | JSON-RPC envelope and error codes | Wire protocol | M (3) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md), [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md) | Not started |
| [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md) | In-house command-line argument parser | CLI | M (3) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-010](KNSH-010-sqlite-ffi-binding.md) | SQLite FFI binding | Platform | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | Not started |

### Phase 1 — Observe (advisory)

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md) | Engine directories, permissions and backup exclusion | Daemon | S (2) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | Not started |
| [KNSH-012](KNSH-012-launchd-user-agent-and-socket-activation.md) | launchd user agent and socket activation | Daemon | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | Not started |
| [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md) | `knshd` connection server, dispatcher and idle exit | Daemon | XL (8) | [KNSH-008](KNSH-008-json-rpc-envelope-and-error-codes.md), [KNSH-012](KNSH-012-launchd-user-agent-and-socket-activation.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | Not started |
| [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md) | `hello` handshake, method catalogue and capability probe v1 | API / Daemon | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md) | Not started |
| [KNSH-015](KNSH-015-session-model-and-registry.md) | Session model and registry | Sessions | M (3) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | Not started |
| [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md) | Record store with `records.query` and `records.output` | Records / API | XL (8) | [KNSH-010](KNSH-010-sqlite-ffi-binding.md), [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | Not started |
| [KNSH-017](KNSH-017-record-retention-and-forget.md) | Record retention and `forget` | Records | L (5) | [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-023](KNSH-023-cli-knsh-history-and-knsh-events.md) | Not started |
| [KNSH-018](KNSH-018-event-bus-and-subscriptions.md) | Event bus and subscriptions | Events / API | XL (8) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | Not started |
| [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | Integration mode: hosting stock zsh | Human shell | L (5) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md) | Not started |
| [KNSH-020](KNSH-020-integration-mode-hosting-stock-bash.md) | Integration mode: hosting stock bash | Human shell | L (5) | [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | Not started |
| [KNSH-021](KNSH-021-human-telemetry-recording-indicator-and-idle-event.md) | Human telemetry, recording indicator and idle event | Human shell | L (5) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | Not started |
| [KNSH-022](KNSH-022-osc-7-osc-133-and-login-shell-support.md) | OSC 7, OSC 133 and login shell support | Human shell | L (5) | [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | Not started |
| [KNSH-023](KNSH-023-cli-knsh-history-and-knsh-events.md) | CLI: `knsh history` and `knsh events` | CLI | M (3) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md), [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-018](KNSH-018-event-bus-and-subscriptions.md) | Not started |
| [KNSH-024](KNSH-024-phase-1-qualification-start-up-benchmark-and-advisory.md) | Phase 1 qualification: start-up benchmark and advisory labelling | Qualification | S (2) | [KNSH-021](KNSH-021-human-telemetry-recording-indicator-and-idle-event.md) | Not started |

### Phase 2 — Contain and decide

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md) | Spike: Seatbelt behaviour (C1, C2, C8) | Spikes | XL (8) | — | Not started |
| [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | Spike: code-signed identity: Keychain, Touch ID from launchd and XPC peer requirements (C5, C6, C7) | Spikes | XL (8) | — | Not started |
| [KNSH-027](KNSH-027-spike-per-command-proxy-credentials-and-tls-server-names.md) | Spike: per-command proxy credentials and TLS server names with common tools (C9, C10) | Spikes | M (3) | — | Not started |
| [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md) | Bash lexer: words, operators and every quoting form | Parser | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | Bash parser: simple commands, assignments, pipelines, lists, redirections | Parser | L (5) | [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md) | Not started |
| [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md) | Bash parser: compound commands and function definitions | Parser | L (5) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | Not started |
| [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md) | Bash parser: command substitution, backticks and here-documents | Parser | L (5) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | Not started |
| [KNSH-032](KNSH-032-parser-limits-and-dynamic-fallback.md) | Parser limits and dynamic fallback | Parser | M (3) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md), [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md), [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md) | Not started |
| [KNSH-033](KNSH-033-agent-command-corpus-pipeline.md) | Agent-command corpus pipeline | Parser | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | Not started |
| [KNSH-034](KNSH-034-differential-parser-tests-against-bash-phase-2-exit.md) | Differential parser tests against bash (phase 2 exit criterion) | Parser | L (5) | [KNSH-032](KNSH-032-parser-limits-and-dynamic-fallback.md), [KNSH-033](KNSH-033-agent-command-corpus-pipeline.md) | Not started |
| [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | Binary resolution and trusted folders | Classifier | M (3) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | Not started |
| [KNSH-036](KNSH-036-wrapper-unwrapping-and-dynamic-code-classification.md) | Wrapper unwrapping and dynamic-code classification | Classifier | XL (8) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | Not started |
| [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md) | Subcommand normalisation and network-intent classes | Classifier | L (5) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | Not started |
| [KNSH-038](KNSH-038-line-re-serialisation-with-resolved-absolute-paths.md) | Line re-serialisation with resolved absolute paths | Classifier | L (5) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | Not started |
| [KNSH-039](KNSH-039-policy-profile-model-and-loader.md) | Policy profile model and loader | Policy | L (5) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md), [KNSH-006](KNSH-006-toml-subset-parser.md) | Not started |
| [KNSH-040](KNSH-040-rule-matching-and-precedence.md) | Rule matching and precedence | Policy | L (5) | [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md), [KNSH-039](KNSH-039-policy-profile-model-and-loader.md) | Not started |
| [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md) | Line verdicts, dynamic-code limits, fixed denies and the `unattended` profile | Policy | L (5) | [KNSH-036](KNSH-036-wrapper-unwrapping-and-dynamic-code-classification.md), [KNSH-040](KNSH-040-rule-matching-and-precedence.md) | Not started |
| [KNSH-042](KNSH-042-grants.md) | Grants | Policy | M (3) | [KNSH-040](KNSH-040-rule-matching-and-precedence.md) | Not started |
| [KNSH-043](KNSH-043-policy-check-dry-run.md) | `policy.check` dry run | Policy | S (2) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md) | Not started |
| [KNSH-044](KNSH-044-seatbelt-compiler-file-rules-and-fixed-denies.md) | Seatbelt compiler: file rules and fixed denies | Sandbox | L (5) | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-039](KNSH-039-policy-profile-model-and-loader.md) | Not started |
| [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | Seatbelt compiler: executables, services, sockets, network, process info, profile files and hashes | Sandbox | XL (8) | [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md), [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-044](KNSH-044-seatbelt-compiler-file-rules-and-fixed-denies.md) | Not started |
| [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md) | `knsh-exec` trampoline and sandbox capability probe | Sandbox | XL (8) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | Not started |
| [KNSH-047](KNSH-047-sandbox-violation-reader.md) | Sandbox violation reader | Sandbox | L (5) | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | Not started |
| [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md) | `agent.sock` endpoint, session tokens and audit-token fallback | Supervisor | L (5) | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | Not started |
| [KNSH-049](KNSH-049-agent-client-knsh-c-forwarding-descriptor-passing-and-shims.md) | Agent client: `knsh -c` forwarding, descriptor passing and shims | Supervisor | XL (8) | [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md) | Not started |
| [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | Supervisor lifecycle orchestrator | Supervisor | XL (8) | [KNSH-038](KNSH-038-line-re-serialisation-with-resolved-absolute-paths.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md), [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md) | Not started |
| [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md) | Spawning: interpreter selection, process groups and timeouts | Supervisor | L (5) | [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | Not started |
| [KNSH-052](KNSH-052-agent-execution-records.md) | Agent execution records | Supervisor | M (3) | [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | Not started |
| [KNSH-053](KNSH-053-output-capture-command-output-and-exec-with-output-modes.md) | Output capture, `command.output` and `exec.*` with output modes | Supervisor | XL (8) | [KNSH-018](KNSH-018-event-bus-and-subscriptions.md), [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md) | Not started |
| [KNSH-054](KNSH-054-pause-resume-and-human-control.md) | Pause, resume and human control | Supervisor | L (5) | [KNSH-015](KNSH-015-session-model-and-registry.md), [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md) | Not started |
| [KNSH-055](KNSH-055-rate-limiting-of-repeated-denials.md) | Rate limiting of repeated denials | Supervisor | S (2) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | Not started |
| [KNSH-056](KNSH-056-knsh-agent-and-session-start-agent.md) | `knsh agent` and `session.start_agent` | Envelope | M (3) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md), [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | Not started |
| [KNSH-057](KNSH-057-envelope-profile-and-launch.md) | Envelope profile and launch | Envelope | L (5) | [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md), [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-049](KNSH-049-agent-client-knsh-c-forwarding-descriptor-passing-and-shims.md), [KNSH-056](KNSH-056-knsh-agent-and-session-start-agent.md) | Not started |
| [KNSH-058](KNSH-058-agent-cli-presets-claude-code-codex-cli-generic.md) | Agent CLI presets (Claude Code, Codex CLI, generic) | Envelope | L (5) | [KNSH-057](KNSH-057-envelope-profile-and-launch.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md) | Not started |
| [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md) | Proxy core: HTTP CONNECT, SOCKS5 and per-command credentials | Proxy | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-027](KNSH-027-spike-per-command-proxy-credentials-and-tls-server-names.md) | Not started |
| [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md) | Proxy connection rules: host rules, address checks and reporting | Proxy | XL (8) | [KNSH-018](KNSH-018-event-bus-and-subscriptions.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md), [KNSH-052](KNSH-052-agent-execution-records.md), [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md) | Not started |
| [KNSH-061](KNSH-061-tls-server-name-check.md) | TLS server-name check | Proxy | L (5) | [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md) | Not started |
| [KNSH-062](KNSH-062-hook-configuration-and-runner.md) | Hook configuration and runner | Hooks | XL (8) | [KNSH-006](KNSH-006-toml-subset-parser.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | Not started |
| [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md) | Verdict combination and rewrite chain | Hooks | M (3) | [KNSH-062](KNSH-062-hook-configuration-and-runner.md) | Not started |
| [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | LocalAuthentication service (Touch ID or password) | Authority | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | Not started |
| [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md) | Policy file signing and `knsh policy edit` | Authority | L (5) | [KNSH-039](KNSH-039-policy-profile-model-and-loader.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | Not started |
| [KNSH-066](KNSH-066-local-approvals-approval-knsh-approvals-knsh-approve.md) | Local approvals: `approval.*`, `knsh approvals`, `knsh approve` | Authority | M (3) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | Not started |
| [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md) | XPC control service with peer verification | Authority | XL (8) | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | Not started |
| [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | `knsh authority trust` and authority registration | Authority | L (5) | [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md), [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md) | Not started |
| [KNSH-069](KNSH-069-decision-protocol.md) | Decision protocol | Authority | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | Not started |
| [KNSH-070](KNSH-070-rewrites.md) | Rewrites | Authority | M (3) | [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md), [KNSH-069](KNSH-069-decision-protocol.md) | Not started |
| [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | Control methods: `session.*`, `policy.*`, `recording.set` | Authority | L (5) | [KNSH-042](KNSH-042-grants.md), [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | Not started |
| [KNSH-072](KNSH-072-pushed-policy-expiry-and-knsh-profile-use.md) | Pushed-policy expiry and `knsh profile use` | Authority | M (3) | [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | Not started |
| [KNSH-073](KNSH-073-policy-grant-on-user-sock-with-touch-id.md) | `policy.grant` on `user.sock` with Touch ID | Authority | S (2) | [KNSH-042](KNSH-042-grants.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | Done |
| [KNSH-074](KNSH-074-fail-closed-operation-and-state-across-restarts.md) | Fail-closed operation and state across restarts | Reliability | M (3) | [KNSH-042](KNSH-042-grants.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | Done |
| [KNSH-075](KNSH-075-threat-model-end-to-end-suite.md) | Threat-model end-to-end suite | Qualification | XL (8) | [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-055](KNSH-055-rate-limiting-of-repeated-denials.md), [KNSH-057](KNSH-057-envelope-profile-and-launch.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-061](KNSH-061-tls-server-name-check.md), [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-066](KNSH-066-local-approvals-approval-knsh-approvals-knsh-approve.md), [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md), [KNSH-073](KNSH-073-policy-grant-on-user-sock-with-touch-id.md) | Done |
| [KNSH-076](KNSH-076-phase-2-qualification-performance-and-tool-compatibility.md) | Phase 2 qualification: performance and tool compatibility | Qualification | L (5) | [KNSH-053](KNSH-053-output-capture-command-output-and-exec-with-output-modes.md), [KNSH-058](KNSH-058-agent-cli-presets-claude-code-codex-cli-generic.md) | Not started |

### Phase 3 — Reverse and protect

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md) | Spike: file-system behaviour: copy-on-write cloning, memory-mapped writes and file-event flushing (C3, C4) | Spikes | XL (8) | — | Done |
| [KNSH-078](KNSH-078-apfs-platform-services-and-checkpoint-storage-layout.md) | APFS platform services and checkpoint storage layout | Checkpoints | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md), [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md) | Done |
| [KNSH-079](KNSH-079-shadow-builder.md) | Shadow builder | Checkpoints | L (5) | [KNSH-078](KNSH-078-apfs-platform-services-and-checkpoint-storage-layout.md) | Not started |
| [KNSH-080](KNSH-080-file-event-watcher-and-rescans.md) | File-event watcher and rescans | Checkpoints | L (5) | [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md), [KNSH-079](KNSH-079-shadow-builder.md) | Not started |
| [KNSH-081](KNSH-081-change-attribution.md) | Change attribution | Checkpoints | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-080](KNSH-080-file-event-watcher-and-rescans.md) | Not started |
| [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) | Capture: pre-images and post-image identity | Checkpoints | L (5) | [KNSH-081](KNSH-081-change-attribution.md) | Not started |
| [KNSH-083](KNSH-083-history-tree.md) | History tree | Checkpoints | M (3) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | Not started |
| [KNSH-084](KNSH-084-undo-and-redo.md) | Undo and redo | Checkpoints | XL (8) | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md), [KNSH-083](KNSH-083-history-tree.md) | Not started |
| [KNSH-085](KNSH-085-possibly-torn-detection.md) | Possibly-torn detection | Checkpoints | M (3) | [KNSH-084](KNSH-084-undo-and-redo.md) | Not started |
| [KNSH-086](KNSH-086-checkpoint-restore-and-checkpoint-diff.md) | `checkpoint.restore` and `checkpoint.diff` | Checkpoints | L (5) | [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md), [KNSH-084](KNSH-084-undo-and-redo.md) | Not started |
| [KNSH-087](KNSH-087-exclusions-retention-and-sensitive-files.md) | Exclusions, retention and sensitive files | Checkpoints | M (3) | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) | Not started |
| [KNSH-088](KNSH-088-checkpoint-api-and-cli.md) | Checkpoint API and CLI | Checkpoints | M (3) | [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md), [KNSH-084](KNSH-084-undo-and-redo.md), [KNSH-086](KNSH-086-checkpoint-restore-and-checkpoint-diff.md) | Not started |
| [KNSH-089](KNSH-089-secret-stores-keychain-and-authority-supplied-secrets.md) | Secret stores: Keychain and authority-supplied secrets | Secrets | L (5) | [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | Not started |
| [KNSH-090](KNSH-090-redaction-engine.md) | Redaction engine | Secrets | L (5) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | Not started |
| [KNSH-091](KNSH-091-redaction-on-every-output-path.md) | Redaction on every output path | Secrets | M (3) | [KNSH-052](KNSH-052-agent-execution-records.md), [KNSH-062](KNSH-062-hook-configuration-and-runner.md), [KNSH-069](KNSH-069-decision-protocol.md), [KNSH-090](KNSH-090-redaction-engine.md) | Not started |
| [KNSH-092](KNSH-092-secret-injection-and-network-narrowing.md) | Secret injection and network narrowing | Secrets | L (5) | [KNSH-042](KNSH-042-grants.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-089](KNSH-089-secret-stores-keychain-and-authority-supplied-secrets.md), [KNSH-091](KNSH-091-redaction-on-every-output-path.md) | Not started |
| [KNSH-093](KNSH-093-irreversible-actions-classification-post-run-marking.md) | Irreversible actions: classification, post-run marking, approvals and undo reporting | Irreversible | XL (8) | [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md), [KNSH-084](KNSH-084-undo-and-redo.md) | Not started |
| [KNSH-094](KNSH-094-endpoint-security-descendant-client-macos-27-entitlement.md) | Endpoint Security descendant client (macOS 27+, entitlement-gated) | Endpoint Security | XL (8) | [KNSH-057](KNSH-057-envelope-profile-and-launch.md) | Not started |
| [KNSH-095](KNSH-095-phase-3-performance-qualification.md) | Phase 3 performance qualification | Qualification | M (3) | [KNSH-084](KNSH-084-undo-and-redo.md) | Not started |

### Phase 4 — Native interpreter

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | Interpreter core and AST evaluator | Interpreter | XL (8) | [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md), [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md) | Not started |
| [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md) | Parameter, variable and arithmetic expansion | Expansion | XL (8) | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | Not started |
| [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md) | Word splitting, quote removal and pathname expansion | Expansion | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md) | Not started |
| [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | Redirections and descriptor management | Execution | L (5) | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | Not started |
| [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md) | Pipelines, subshells and job control | Execution | XL (8) | [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | Not started |
| [KNSH-101](KNSH-101-core-builtins.md) | Core builtins | Builtins | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | Not started |
| [KNSH-102](KNSH-102-builtins-test-printf-read.md) | Builtins: `test`, `[[ ]]`, `printf`, `read` | Builtins | L (5) | [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md), [KNSH-101](KNSH-101-core-builtins.md) | Not started |
| [KNSH-103](KNSH-103-functions-scopes-and-arrays.md) | Functions, scopes and arrays | Language | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md) | Not started |
| [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md) | Traps, signals, `set` and `shopt` options | Language | L (5) | [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md), [KNSH-101](KNSH-101-core-builtins.md) | Not started |
| [KNSH-105](KNSH-105-process-substitution-coproc-and-here-documents.md) | Process substitution, `coproc` and here-documents | Execution | M (3) | [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md) | Not started |
| [KNSH-106](KNSH-106-posix-mode.md) | POSIX mode | Compatibility | M (3) | [KNSH-101](KNSH-101-core-builtins.md), [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md) | Not started |
| [KNSH-107](KNSH-107-interactive-line-editor-and-history.md) | Interactive line editor and history | Interactive | XL (8) | [KNSH-101](KNSH-101-core-builtins.md) | Not started |
| [KNSH-108](KNSH-108-per-simple-command-decisions.md) | Per-simple-command decisions | Supervision | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | Not started |
| [KNSH-109](KNSH-109-conformance-gate-bash-test-suite-oils-subset-99-corpus.md) | Conformance gate: bash test suite, Oils subset, 99% corpus | Qualification | L (5) | [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md), [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md), [KNSH-101](KNSH-101-core-builtins.md), [KNSH-102](KNSH-102-builtins-test-printf-read.md), [KNSH-103](KNSH-103-functions-scopes-and-arrays.md), [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md), [KNSH-105](KNSH-105-process-substitution-coproc-and-here-documents.md), [KNSH-106](KNSH-106-posix-mode.md), [KNSH-107](KNSH-107-interactive-line-editor-and-history.md), [KNSH-108](KNSH-108-per-simple-command-decisions.md) | Not started |

### Phase 5 — Linux

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Portable platform split and Linux CI | Platform | M (3) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | Not started |
| [KNSH-111](KNSH-111-in-house-sha-256-and-hmac-replacing-commoncrypto.md) | In-house SHA-256 and HMAC replacing CommonCrypto | Platform | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-112](KNSH-112-systemd-units-socket-activation-and-control-channel-with-so.md) | systemd units, socket activation and control channel with `SO_PEERCRED` | Daemon / Authority | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md) | Landlock and seccomp in `knsh-exec` | Sandbox | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-114](KNSH-114-network-confinement-seccomp-or-network-namespace.md) | Network confinement: seccomp or network namespace | Network | L (5) | [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md) | Not started |
| [KNSH-115](KNSH-115-inotify-fanotify-watcher-and-reflink-checkpoints.md) | inotify/fanotify watcher and reflink checkpoints | Checkpoints | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-116](KNSH-116-secret-service-backend.md) | Secret Service backend | Secrets | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-117](KNSH-117-journald-logging-and-violation-reading.md) | journald logging and violation reading | Observability | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-118](KNSH-118-spike-user-presence-check-for-approvals-on-linux.md) | Spike: user-presence check for approvals on Linux | Authority | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | Not started |
| [KNSH-119](KNSH-119-linux-qualification.md) | Linux qualification | Qualification | L (5) | [KNSH-111](KNSH-111-in-house-sha-256-and-hmac-replacing-commoncrypto.md), [KNSH-112](KNSH-112-systemd-units-socket-activation-and-control-channel-with-so.md), [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md), [KNSH-114](KNSH-114-network-confinement-seccomp-or-network-namespace.md), [KNSH-115](KNSH-115-inotify-fanotify-watcher-and-reflink-checkpoints.md), [KNSH-116](KNSH-116-secret-service-backend.md), [KNSH-117](KNSH-117-journald-logging-and-violation-reading.md), [KNSH-118](KNSH-118-spike-user-presence-check-for-approvals-on-linux.md) | Not started |

### Phase 6 — Later (unsized backlog)

These items come from the roadmap and the decision log but have no specification yet. They are **unsized**: each one
first needs its own spec page with requirement IDs and acceptance checks. Only then can it be split into sized
stories. The only acceptance criterion for now is "spec page written and reviewed".

| ID | Title | Epic | Size | Depends on | Status |
| --- | --- | --- | --- | --- | --- |
| [KNSH-120](KNSH-120-command-introspection.md) | Command introspection | — | unsized | — | Not started |
| [KNSH-121](KNSH-121-mcp-client.md) | MCP client | — | unsized | — | Not started |
| [KNSH-122](KNSH-122-session-replay.md) | Session replay | — | unsized | — | Not started |
| [KNSH-123](KNSH-123-optional-structured-pipelines.md) | Optional structured pipelines | — | unsized | — | Not started |
| [KNSH-124](KNSH-124-opt-in-knsh-corpus-export.md) | Opt-in `knsh corpus export` | — | unsized | — | Not started |
| [KNSH-125](KNSH-125-revisit-agents-as-a-separate-macos-user-managed-deployments.md) | Revisit: agents as a separate macOS user (managed deployments) | — | unsized | — | Not started |
