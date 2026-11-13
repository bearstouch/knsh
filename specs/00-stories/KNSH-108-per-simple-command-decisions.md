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
- [ ] In native mode, every external command in a script or function receives its own decision and record.
- [ ] Commands built by `eval`, `source` or variables are decided after expansion, with their real argv.
- [ ] A denied simple command fails with 126 inside the script and the reason on stderr; the script continues
      according to bash semantics (`set -e` etc.).
- [ ] The supervisor, not the interpreter, spawns agent commands; the interpreter cannot grant itself more
      (NFR-SEC-02).
- [ ] When the supervisor is unreachable, no command runs (NFR-REL-01).
- [ ] Phase 2 line-level behaviour remains available and unchanged for sessions not using native mode.

**Unit tests**
- `each_external_command_requests_decision`
- `eval_command_decided_after_expansion`
- `denied_command_returns_126_inside_script`
- `errexit_stops_script_after_denial`
- `unreachable_supervisor_denies_everything`

**Integration tests**
- Agent session in native mode: a script with `eval "git push"` asks the authority for `git push` specifically.

**Notes.** Spec gap: how a native-mode agent session is selected (profile key? `knsh agent --native`?) and how the
per-command records relate to the line record are not specified. Write the spec section first.
