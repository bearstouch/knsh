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
- [x] `PIPESTATUS` and `pipefail` match bash; the record's `pipestatus` field can be filled from it. *Unit tests
      `pipestatus_records_each_stage`, `pipefail_returns_rightmost_failure`; compared with `/bin/bash` 3.2 with real
      processes and pipes (`pipeline_script_matches_bash`, `pipefail_matches_bash`). `ShellState::pipestatus()` is the
      value a record's `pipestatus` takes (wired with KNSH-108).*
- [x] Each pipeline runs in its own process group in interactive mode; job control works in a real terminal. *Unit
      test `interactive_pipelines_get_their_own_process_group`; the PTY test `terminal_job_control_matches_bash` runs
      `sleep 30`, Ctrl-Z, `jobs`, `bg`, `jobs`, `fg`, Ctrl-C under a pseudo-terminal and prints bash 3.2's lines.
      The interactive host is a test loop until KNSH-107 brings the line editor.*
- [x] Non-interactive scripts do not create job-control process groups, like bash. *Unit test
      `scripts_do_not_create_process_groups`; with real processes the jobs of a script are in the shell's own group
      (`pause_and_resume_reach_every_job_group`).*
- [x] `wait -n` and `$!` match bash. *Unit tests `wait_n_returns_first_finished_job`, `background_job_sets_last_pid`;
      `$!` and `wait` compared with `/bin/bash` 3.2. `wait -n` is bash 4.3 and later, so it is checked against bash
      5.2's documented behaviour only: pending a bash 5.2 run (KNSH-109).*
- [x] No PID is signalled after it may have been reused: jobs keep handles, not bare PIDs (`CLAUDE.md`). *Children
      are `ChildHandle`s (process id plus a generation private to the spawner); a job's group is signalled only
      through `Processes::signal_job`, which refuses once no member is held unreaped (`spawn_child_places_children_in_groups`,
      `places_groups_and_resumes_stopped_runs`), and joining a group is checked and done under the same lock.*

**Unit tests**
- `pipestatus_records_each_stage`
- `pipefail_returns_rightmost_failure`
- `lastpipe_runs_last_stage_in_shell`
- `subshell_changes_do_not_leak`
- `background_job_sets_last_pid`
- `wait_n_returns_first_finished_job`
- `time_keyword_reports_times`
- Also: `scripts_do_not_create_process_groups`, `interactive_pipelines_get_their_own_process_group`,
  `stopped_jobs_resume_with_bg_and_fg`, `stopped_subshell_is_reported_and_resumed`, `fg_refuses_a_job_that_ended`,
  `pause_and_resume_signal_every_job_group`,
  `pipe_all_joins_standard_error_after_redirections`, `job_builtin_errors_match_bash`, `pipelines_reap_every_child`,
  `job_status_follows_pipefail_and_negation`, `job_lines_match_bash`, `time_formats_follow_bash` (`knsh-interp`);
  `spawn_child_places_children_in_groups`, `wait_child_reports_stops_and_continues`,
  `child_signals_are_set_before_exec`, `places_groups_and_resumes_stopped_runs`,
  `take_refuses_what_is_not_a_terminal`, `cpu_times_grow_and_elapsed_is_monotonic` (`knsh-platform`).

**Integration tests**
- PTY-based test: start a job, `Ctrl-Z`, `bg`, `fg`, `jobs`; compare with bash. *`crates/knsh-interp/tests/job_control.rs`
  `terminal_job_control_matches_bash` (against `/bin/bash -i` 3.2 under `/usr/bin/script`).*
- Pause and resume from the supervisor stop and continue every job's process group. *`job_control.rs`
  `pause_and_resume_reach_every_job_group` (real processes, `ps` state `T` and back).*
- Also `crates/knsh-interp/tests/bash_differential.rs` `pipeline_script_matches_bash`, `pipefail_matches_bash`.

**Implementation notes (KNSH-100).** Commands start through `CommandSpawner::start` and are waited for with
`CommandSpawner::wait`, which also reports stops and continues (`ChildEvent`); `run` is now start-then-wait.
`Processes::spawn_child` places a child as `ChildOptions` says: in the caller's group (`Inherit`, every command of a
shell without job control, as bash runs a script, so the supervisor's `SIGSTOP` to the line's group reaches it), as
the leader of a new group (`Lead`) or in a held group (`Join`); for a foreground job's leader it hands the terminal to
the new group in the child before `exec` (`tcsetpgrp` with `SIGTTOU` blocked) and sets the job-control signals to
their default (`ChildSignals::Default`); an asynchronous command without job control ignores `SIGINT` and `SIGQUIT`
(`IgnoreInterrupt`). `SystemTerminal` takes an interactive shell's terminal (ignores `SIGTSTP`, `SIGTTIN`, `SIGTTOU`,
leads its group, saves the terminal modes and restores them when it takes the terminal back); `SystemShellTimes`
gives `time` a monotonic clock and `getrusage` of the process and its children. `Descriptors::pipe` makes the pipes.

The interpreter cannot fork its multithreaded process, so a subshell is a copy of the interpreter (variables,
options, working directory, descriptor table), sharing only the injected effects and the message writers
([decision 19](../09-reference/decisions.md)). In a pipeline, a simple command is expanded in its copy and its
program started without waiting; any other command runs in its copy on a thread of its own; a pipeline of one simple
command runs in the shell itself, as does the last command under `lastpipe` without job control. Each child has a
thread blocked in `wait` that sends what happens to the shell over one channel, so the shell waits for whichever job
it needs (`wait -n`) and every child is reaped. `PIPESTATUS` is read as `$PIPESTATUS`, `${PIPESTATUS[@]}`, `[*]`,
`[n]` (negative from the end) and `${#PIPESTATUS[@]}`; assigning it and any subscript that needs arithmetic stay
refused until arrays (KNSH-103). `set -o pipefail`, `shopt -s lastpipe` and `set -m` are `ShellOptions::pipefail`,
`lastpipe` and `monitor` until `set` and `shopt` (KNSH-104). `Interpreter::with_job_control` makes an interactive
shell (`$-` holds `i` and `m`, `[n] pid` for background jobs, `Interpreter::notify_jobs` before each prompt);
`Interpreter::job_signals` is the supervisor's handle to stop and continue every job's group (FR-SES-10); stops it
causes are not taken for Ctrl-Z. The job builtins `wait` (`-n`), `jobs` (`-lprs`), `fg`, `bg` and `disown` (`-ahr`)
are native; `time` and `time -p` honour `TIMEFORMAT` and are refused when the interpreter was given no clocks
(`Interpreter::with_times`). Finished background jobs are remembered for `wait` up to 1,024
([limits](../09-reference/defaults-and-limits.md)).

Command substitution, which earlier stories deferred here, is not in this story's scope: it moves to
[KNSH-105](KNSH-105-process-substitution-coproc-and-here-documents.md), which shares its capture of a subshell's
output. Differences from bash are listed in [compatibility](../04-non-functional-requirements/compatibility.md).

Pending: a run against bash 5.2 (only 3.2 is installed here; KNSH-109) for `wait -n`, `|&` and `lastpipe` (bash 4
and later); a real `knsh` interactive host (KNSH-107); the full workspace suite (not requested).
