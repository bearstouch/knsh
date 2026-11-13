# KNSH-100 — Pipelines, subshells and job control

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Execution | XL (8) | [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02, FR-SES-10 |

**Description.** As an interactive user and as an agent, I want pipelines, subshells, background jobs and job
control to match bash, so that both scripts and interactive use behave the same.

Scope: pipelines with `PIPESTATUS`, `pipefail`, `lastpipe`, `|&`, `( )` subshells, `&` background jobs, `$!`, `wait`
(including `wait -n`), process groups, terminal foreground control (`tcsetpgrp`) in interactive mode, `jobs`, `fg`,
`bg`, `disown`, `SIGTSTP` handling, `time` keyword. Process groups must stay compatible with the supervisor's pause
(`SIGSTOP`/`SIGCONT` to process groups, FR-SES-10).

**Acceptance criteria**
- [ ] `PIPESTATUS` and `pipefail` match bash; the record's `pipestatus` field can be filled from it.
- [ ] Each pipeline runs in its own process group in interactive mode; job control works in a real terminal.
- [ ] Non-interactive scripts do not create job-control process groups, like bash.
- [ ] `wait -n` and `$!` match bash.
- [ ] No PID is signalled after it may have been reused: jobs keep handles, not bare PIDs (`CLAUDE.md`).

**Unit tests**
- `pipestatus_records_each_stage`
- `pipefail_returns_rightmost_failure`
- `lastpipe_runs_last_stage_in_shell`
- `subshell_changes_do_not_leak`
- `background_job_sets_last_pid`
- `wait_n_returns_first_finished_job`
- `time_keyword_reports_times`

**Integration tests**
- PTY-based test: start a job, `Ctrl-Z`, `bg`, `fg`, `jobs`; compare with bash.
- Pause and resume from the supervisor stop and continue every job's process group.
