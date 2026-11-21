# KNSH-101 — Core builtins

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Builtins | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** As a script author, I want the commonly used bash builtins to behave like bash, so that scripts and
rc files run unchanged.

Scope: `cd` (with `CDPATH`, `-P`, `-L`, `OLDPWD`), `pwd`, `export`, `unset`, `readonly`, `declare`/`typeset`
(non-array attributes), `local` (scoping in 409), `shift`, `set` (positional parameters; options in 410), `exit`,
`return`, `break`, `continue`, `true`, `false`, `:`, `echo` (bash and `xpg_echo` behaviour), `eval`, `source`/`.`,
`command`, `builtin`, `type`, `hash`, `alias`/`unalias` (with `expand_aliases`), `umask`, `exec`.

**Acceptance criteria**
- [x] Every listed builtin matches bash 5.2 for exit status, output and error message shape. *Unit tests in
      `crates/knsh-interp/src/eval/tests/builtins.rs` give each builtin's messages and statuses, checked against
      `/bin/bash` 3.2 and, where 3.2 differs, bash 5.2's source ([compatibility](../04-non-functional-requirements/compatibility.md));
      `builtin_script_matches_bash` runs a script of every builtin under the interpreter (real processes and
      filesystem) and under `/bin/bash` and compares output and status. Forms later stories implement are refused,
      never approximated: `set` with options or alone (KNSH-104), arrays and `declare -n` (KNSH-103), listings that
      would show variables bash maintains itself (`declare -p` alone, `readonly -p`), `local` inside a function
      (functions: KNSH-103). Pending: a run against bash 5.2 itself (only 3.2 is installed; KNSH-109).*
- [ ] `cd` emits OSC 7 after changing directory (NFR-COMPAT-10) and `cwd.changed` when recording. *Done in the
      interpreter: after each successful `cd` (not a subshell's) it calls the host's `DirectoryObserver`, and
      `knsh_interp::Osc7` writes the sequence `knsh`'s integration mode writes (`cd_reports_each_change_to_the_directory_observer`,
      `osc7_observer_writes_the_sequence`). Pending: the host that publishes `cwd.changed` from the observer while
      recording and writes OSC 7 only to a terminal (the native shell's host, KNSH-107 and KNSH-108).*
- [x] `eval` and `source` go through the same per-command decision path as any other command (KNSH-108). *Their text
      is parsed, checked and evaluated by the same evaluator, so every program in it starts through
      `CommandSpawner`, the seam KNSH-108 wraps (`eval_and_source_run_commands_through_the_spawner`). The decision
      itself arrives with KNSH-108.*
- [x] Aliases expand only when `expand_aliases` is on, as in bash (on in interactive mode). *`alias_expansion_requires_expand_aliases`:
      a script defines and lists aliases but never expands them; `Interpreter::with_job_control` turns
      `expand_aliases` on; an alias is expanded only in lines read after it was defined, as bash reads a line at a
      time.*

**Unit tests**
- `cd_uses_cdpath_and_sets_oldpwd`
- `cd_physical_resolves_symlinks`
- `export_marks_variable_for_children`
- `readonly_blocks_assignment`
- `echo_escape_handling_matches_bash_and_xpg_echo`
- `return_outside_function_is_error`
- `alias_expansion_requires_expand_aliases`
- `type_reports_builtin_function_alias_file` (functions cannot be defined until KNSH-103, so none is ever reported)
- Also: `cd_errors_match_bash`, `cd_reports_each_change_to_the_directory_observer`,
  `cd_with_a_readonly_pwd_changes_directory_and_fails`, `oldpwd_starts_exported_without_a_value`,
  `declare_attributes_and_printing`, `unset_removes_variables_and_reports_bad_names`,
  `assignments_before_builtins_are_temporary`, `break_and_continue_leave_and_resume_loops`,
  `exit_shift_and_set_follow_bash`, `eval_and_source_run_commands_through_the_spawner`, `nested_messages_follow_bash`,
  `syntax_errors_in_eval_and_source_are_reported_like_bash`, `command_finds_and_describes_without_functions`,
  `hash_remembers_commands_like_bash`, `exec_runs_the_program_and_ends_the_shell`, `alias_builtin_errors_match_bash`,
  `umask_is_printed_set_and_passed_on`, `declaration_builtins_keep_the_temporary_assignments_they_mark`,
  `nested_text_running_at_once_is_bounded`, `exec_of_a_program_that_cannot_start_keeps_an_interactive_shell`
  (`knsh-interp`); `spawn_sets_the_requested_umask`,
  `masked_opens_create_files_with_the_shell_umask` (`knsh-platform`).

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `builtin_script_matches_bash` (against `/bin/bash` 3.2).

**Implementation notes (KNSH-101).** Variables have attributes (`-x`, `-r`, `-i`, `-l`, `-u`, `-t`) and may be
declared without a value; every assignment the shell makes (a command's, `for`'s, `${x:=…}`, arithmetic, `{fd}>`,
`cd`'s `PWD`) goes through one path that refuses a read-only variable and applies the integer and case attributes,
as bash's `bind_variable`. An assignment error with no command abandons the line (bash 5.2 outside POSIX mode); before
a command it is reported and the command runs without it. Assignments before a builtin are made for the builtin's run
only and exported to what it starts (bash's temporary environment). The arguments of `declare`, `typeset`, `export`,
`readonly` and `local` spelled like assignments are expanded as assignments. `break`, `continue` and `return` are
stops the loops, `source` and subshells catch. `eval` and `source` text is parsed and checked like the script; its
messages carry the sourced file's name and lines counted from the `eval` command. Bash parses such text a line at a
time, so for a syntax error the lines before the error's line run first, then bash's report, status 2; an error bash
would report differently (an unterminated quote) is refused. The command hash table is kept as bash keeps it (used
before `PATH`, emptied when `PATH` changes, listed in bash's bucket order). `exec cmd` runs the program through the
spawner and ends the shell with its status ([decision 20](../09-reference/decisions.md)). Aliases expand when a
simple command runs, with the aliases of the moment its line started; text that only parses after expansion
(`alias x='if true; then'`) cannot be expanded, and inside a pipeline an alias must expand to one simple command. The
shell's umask is passed to every command (`CommandRequest::umask`, set in the child before `exec`) and to the
redirections that create files (`Descriptors::open_masked`); the host gives the umask the process started with
(`ShellState::with_umask`), and until it does commands keep the process's own and printing it is refused, never
guessed. `cd` changes the interpreter's working directory, never
the process's, after checking the target as `chdir` would; the host is told through `DirectoryObserver`.
