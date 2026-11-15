# KNSH-051 — Spawning: interpreter selection, process groups and timeouts

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | L (5) | [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | `knshd`, `knsh-platform` | FR-LC-13 – FR-LC-17, FR-LC-40, FR-SBX-03, FR-SBX-04 |

**Description.** As the supervisor, I want to spawn each allowed line through `knsh-exec` with the right interpreter,
profile, descriptors and process group, so that the line runs under its own kernel-enforced profile and can be
timed out or stopped reliably.

**Acceptance criteria**
- [x] The line is re-serialised with every command's resolved absolute path (KNSH-038) before spawn.
- [x] `sh` runs `/bin/sh`, `zsh` runs zsh, and `bash` or `knsh -c` run the profile's bash (default `/bin/bash`).
- [ ] The child is started through `knsh-exec` with the compiled profile file, the caller's stdio descriptors, the
      forwarded environment (minus shim `PATH` entries), and the per-command proxy credentials. *Done except the proxy
      credentials, pending KNSH-059 (no proxy exists yet; lines get no proxy port, so their network is closed).*
- [x] Each line runs in its own new process group. `knshd` keeps the group handle and never signals a PID that may
      have been reused.
- [x] `command.started` is emitted at spawn. `command.long_running` is emitted once after 30 s (configurable).
- [x] When `timeout_s` elapses, the whole process group is killed and the call fails with `-32008`, carrying the
      `record_id`. The record's `signal` is set.
- [x] No sandbox is ever applied inside `knshd` between `fork` and `exec` (only `knsh-exec` applies it).
- [x] If `knsh-exec` fails to apply the profile, the line does not run and the failure is recorded.

**Unit tests**
- `selects_bin_sh_for_sh_request` — FR-LC-14.
- `selects_profile_bash_for_knsh_c` — FR-LC-14, NFR-COMPAT-04.
- `strips_shim_directory_from_child_path` — FR-LC-16.
- `kills_process_group_on_timeout_with_32008` — FR-LC-40.
- `emits_long_running_once_after_threshold` — FR-LC-17 (fake clock).
- `refuses_to_run_when_profile_application_fails` — NFR-REL-08.

**Integration tests**
- A swapped binary placed in an untrusted folder after classification fails to exec under the profile (FR-LC-15).
- `sleep 100` with `timeout_s = 1` is killed. No process from its group survives.

**Notes**
- Spec gap: the grace period between SIGTERM and SIGKILL on timeout is not specified. Propose SIGTERM, then SIGKILL
  after 2 s, and record the value in [defaults and limits](../09-reference/defaults-and-limits.md). *Done: recorded
  there.*
- Implemented (see [command lifecycle](../03-functional-requirements/command-lifecycle.md#spawning-knsh-051)):
  `knsh-exec` gained `--arg` (operands) and `--status-fd` (tells a trampoline failure from the line's own exit);
  `command.long_running` is configurable in code (`Limits`) but has no configuration-file key yet; `sandbox-exec`'s
  own exits 65 and 71 cannot be told from the line's and are reported as its exit code.
