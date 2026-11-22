# KNSH-108 — Per-simple-command decisions

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Supervision | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | `knsh-interp`, `knshd` | FR-LC-02 – FR-LC-19, NFR-SEC-02, compatibility table (native mode) |

**Description.** As the authority, I want native-mode agent sessions to decide on every simple command, including
those inside scripts, functions, `eval` and `source`, so that dynamic code no longer has to be treated as an opaque
whole.

Scope: before each external command or dangerous builtin runs, the interpreter submits the resolved command to the
supervisor (same policy, hooks, authority path as phase 2), and the supervisor still spawns it through `knsh-exec`
(one process starts agent commands). Records and events per simple command, linked to the parent line.

**Acceptance criteria**
- [x] In native mode, every external command in a script or function receives its own decision and record.
- [x] Commands built by `eval`, `source` or variables are decided after expansion, with their real argv.
- [x] A denied simple command fails with 126 inside the script and the reason on stderr; the script continues
      according to bash semantics (`set -e` etc.).
- [x] The supervisor, not the interpreter, spawns agent commands; the interpreter cannot grant itself more
      (NFR-SEC-02).
- [x] When the supervisor is unreachable, no command runs (NFR-REL-01).
- [x] Phase 2 line-level behaviour remains available and unchanged for sessions not using native mode.

**Unit tests**
- `each_external_command_requests_decision`
- `eval_command_decided_after_expansion`
- `denied_command_returns_126_inside_script`
- `errexit_stops_script_after_denial`
- `unreachable_supervisor_denies_everything`

**Integration tests**
- Agent session in native mode: a script with `eval "git push"` asks the authority for `git push` specifically.

**Notes.** Spec gap closed in
[command lifecycle, native mode](../03-functional-requirements/command-lifecycle.md#native-mode-knsh-108)
(FR-LC-50 to FR-LC-58) and decision 24: the profile key `exec.mode = "native"` selects it (never the agent); the line
gets a line record (`decision.source = "native"`, no decision of its own) and each command a command record whose
`parent_record_id` names it, as do its `command.denied`, `command.started` and `command.finished`.

**Implementation (KNSH-108).**
- `knsh-platform::supervision`: the channel's messages, `SupervisedSpawner` (the interpreter's `CommandSpawner`,
  failing closed) and the macOS socket link and request reader; `CommandOutcome::Denied` (126 with the supervisor's
  reason already printed).
- `knsh --native-line <fd> <line> [$0 …]`: the interpreter `knshd` starts; `knsh-sandbox`'s
  `CommandTag::Interpreter` (exec of `knsh` only, no `fork`, no network); `knsh-exec --program` and `--in-group`.
- `knshd`: `supervisor/native.rs` serves the channel and decides each command through the phase 2 pipeline;
  `TrampolineSpawner::spawn_native` and `run_command`; records and events carry `parent_record_id` (record schema
  version 3).

**Verified.** Unit tests (the five above, in `knsh-interp`), the channel and protocol tests (`knsh-platform`), the
orchestrator with a fake interpreter on the real channel (`knshd` `supervisor::tests::native`: the integration test
above), and end to end on macOS with the real `knsh`, `knsh-exec` and `sandbox-exec`
(`knshd` `threat_model::native`: `eval "rm …"` denied with 126 and the reason, `set -e`, the interpreter's own
redirection outside the write roots refused by its profile). Pending: the full suite (`cargo test --workspace`), and
native mode against a real authority over XPC.
