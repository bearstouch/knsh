# KNSH-099 — Redirections and descriptor management

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Execution | L (5) | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02 |

**Description.** As a script author, I want every bash redirection to work, so that output, errors and descriptors
go where bash would send them.

Scope: `< > >> >| <> <& >& &> &>> 2>&1`, numbered descriptors, `{var}>` named descriptors, closing with `-`, `noclobber`,
`exec` with redirections only (persistent), here-strings `<<<`, `/dev/stdin`, `/dev/fd/N`, `/dev/tcp` (see notes),
save/restore of descriptors around builtins and functions. Descriptor effects go through `knsh-platform`.

**Acceptance criteria**
- [x] Redirections are applied left to right as in bash (`2>&1 >file` vs `>file 2>&1`). *Unit test
      `redirection_order_matters_like_bash`; compared with `/bin/bash` with real files and processes
      (`redirection_script_matches_bash`).*
- [x] `noclobber` blocks `>` on existing files and `>|` overrides it. *Unit tests; compared with `/bin/bash -C`
      (`noclobber_matches_bash`). `set -C` itself is a builtin (KNSH-104): until then the option is
      `ShellOptions::noclobber`.*
- [x] Redirections on builtins and functions are undone after the command. *Builtins (`let`, `:`, `exec` inside a
      group), external commands and compound commands are restored after the command, newest change first, also when
      a redirection fails part-way. Functions do not exist yet (KNSH-103); a function call will go through the same
      compound-command path.*
- [x] `exec 3>file` persists for the shell; `exec 3>&-` closes it. *Unit test `exec_redirection_persists` (also
      across runs of one `Interpreter`); compared with `/bin/bash`, including `exec >file` and back.*
- [x] Descriptors are not leaked to child processes beyond what bash passes. *A command receives exactly the shell's
      table (`CommandRequest::descriptors`); `/bin/ls /dev/fd` under the native interpreter lists the same
      descriptors as under `/bin/bash`, before, during and after `exec 4>f4`. The spawner places descriptors at their
      numbers and closes every other inheritable one (`knsh-platform` tests `placements_*`).*

**Unit tests**
- `redirection_order_matters_like_bash`
- `noclobber_blocks_overwrite`
- `force_clobber_overrides_noclobber`
- `builtin_redirection_is_restored`
- `exec_redirection_persists`
- `named_fd_assigns_variable`
- `here_string_appends_newline`
- `no_descriptor_leak_to_children`
- Also: `special_names_and_descriptor_forms_follow_bash`, `network_redirections_are_refused`,
  `redirection_errors_match_bash`, `messages_to_a_closed_standard_error_are_dropped` (`knsh-interp`);
  `redirection_variable_is_read_when_enabled` (`knsh-bash`); `placements_swap_standard_descriptors`,
  `placements_set_numbers_above_stdio_and_close`, `placed_spawn_of_missing_program_exits_127`,
  `refuses_invalid_placements`, `descriptor_table_becomes_placements`, `modes_open_like_bash`,
  `noclobber_refuses_existing_regular_files_only`, `never_opens_this_process_descriptor_table`,
  `here_strings_read_back_exactly`, `descriptor_table_paths_are_recognised_in_every_spelling` (`knsh-platform`).

**Integration tests**

- `crates/knsh-interp/tests/bash_differential.rs`: `redirection_script_matches_bash`, `noclobber_matches_bash`
  (against `/bin/bash` 3.2, in forms bash 3.2 and 5.2 agree on).

**Notes.** `/dev/tcp` and `/dev/udp` open network connections from the shell itself. Inside a sandboxed line these
must still be confined by the profile and the proxy (FR-NET-08: no direct network). **Decided:** refused, in every
session ([decision 18](../09-reference/decisions.md)): the redirection fails with a message and status 1, and the
command does not run.

**Implementation notes (KNSH-099).** The interpreter keeps the shell's descriptor table itself (`eval::redirect`):
each number holds one of the spawner's standard descriptors or a file opened through the new
`knsh_platform::Descriptors` trait (`SystemDescriptors` on macOS, `testing::FakeDescriptors` over `MemFs`). Nothing
is moved in the interpreter's own process. A command gets the whole table in `CommandRequest::descriptors`;
`ProcessCommandSpawner` turns it into `SpawnRequest::placements`, which the child applies after its standard
descriptors are set up: every source is copied above the highest target first, so `1>&2 2>&1` swaps, then each target
receives its copy or is closed, and every other inheritable descriptor is closed. With a target above 2 the child
calls `execve` itself (std's pipe that reports a failed `exec` may have been one of the targets), and a failed `exec`
then ends it with 127 or 126.

Each redirection's change is recorded and undone after the command, newest first; `exec` without a command keeps
them, and a redirection that fails undoes those before it (as bash does, `exec` included). `{name}>file` takes the
lowest free number from 10, sets `name`, and is not undone; `{name}>&-` closes the number `name` holds. It is read
only with the new `knsh_bash::ParseOptions::redirection_variables` (bash 3.2 reads `{name}` as a word, so the
default parse still refuses such a line). Targets are expanded as bash expands them (brace, tilde, parameter,
arithmetic, splitting, globbing): anything but one word is `ambiguous redirect`. Here-strings are expanded without
splitting or globbing and get a newline; the real backend passes them through a pipe up to 4 KiB and an unlinked
temporary file (mode `0600`) above. `>&word` and `1>&word` with a word that is not a number are `&>word`, as in bash.

The shell's own messages go to its descriptor 2 as the redirections in force leave it (the diagnostics writer while
it is the spawner's standard error, `Interpreter::with_output` while it is standard output, the file otherwise).
`/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` duplicate the shell's descriptors. The real backend never
opens a path that reaches `/dev/fd`, which in the interpreter's process would duplicate the engine's own descriptors:
paths are opened with `O_NOFOLLOW_ANY` after a check of their text, and a path holding a symlink is resolved,
checked and opened again with `O_NOFOLLOW_ANY`, so a symlink swapped in meanwhile fails the open. `noclobber` follows
bash's `noclobber_open` (`O_EXCL` for a new file, devices still writable). Descriptor numbers stop at 255
([limits](../09-reference/defaults-and-limits.md)). `:` and `exec` with redirections only are native builtins;
`exec cmd` is refused until KNSH-101, here-documents until KNSH-105. Differences from bash are listed in
[compatibility](../04-non-functional-requirements/compatibility.md).

A failed redirection is reported before the ones before it are undone, as bash does (`{ …; } 2>err <missing`
writes the message to `err`); `n>&n-` keeps `n`. In the child, copies of placement sources take the lowest free number
that is not a target, so descriptor 255 works under the default limit of 256.

Pending: a run against bash 5.2 itself (only 3.2 is installed here; KNSH-109), which also covers `{name}>`, `&>>` and
unquoted here-strings, and the full workspace suite (not requested).
