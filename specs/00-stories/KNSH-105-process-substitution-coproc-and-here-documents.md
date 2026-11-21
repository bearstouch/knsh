# KNSH-105 — Process substitution, `coproc` and here-documents

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Execution | M (3) | [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02, decision 6 |

**Description.** As a script author, I want `<( )`, `>( )`, `coproc` and here-documents to work as in bash, so that
advanced scripts run.

Scope: command substitution `$( )` and backquotes (moved here from KNSH-100: it captures a subshell's output as
process substitution does), process substitution via `/dev/fd/N`, `coproc` with named and default (`COPROC`) arrays,
here-documents with and without expansion, `<<-` tab stripping. In phase 2 these were classified as dynamic when fed to shells or
interpreters (decision 6); in native mode each command they run is decided individually (KNSH-108).

**Acceptance criteria**
- [x] `$(cmd)` and `` `cmd` `` give the command's output without its trailing newlines, split and globbed as bash
      does, and `$?` after an assignment is the substitution's status. *The body is parsed again from its text (a
      backtick's un-escaped first) and run in a copy of the shell on its own thread, its output read from a pipe;
      NUL bytes dropped, trailing newlines removed; a command without a name ends with its last substitution's
      status; `set -e` off inside unless `inherit_errexit`; `$(< file)` reads the file.
      `command_substitution_gives_output_split_and_globbed_as_bash`,
      `substitution_status_is_the_status_of_an_assignment`, `errexit_in_command_substitution_follows_inherit_errexit`,
      `command_substitution_of_a_redirection_reads_the_file`, and `substitution_and_here_document_script_matches_bash`
      against `/bin/bash` 3.2.*
- [x] `diff <(a) <(b)` works and descriptors are closed after use. *The shell's end is placed at the highest free
      number below 64 (`/dev/fd/63`, `/dev/fd/62`, as bash), given to the command and read by the shell's own
      redirections (`done < <(cmd)`, `exec 3< <(cmd)`), and closed once the command whose word made it is done.
      `process_substitution_provides_dev_fd_path`, `redirections_read_process_substitutions`, and the differential
      script (real `diff`, `cat`).*
- [ ] `coproc` exposes read/write descriptors and the PID like bash. *Implemented after bash 5.2's
      `execute_coproc`: `COPROC` or `NAME` holds the read and write ends (close-on-exec, at 63 and 62),
      `NAME_PID` and `$!` the process id; a compound coprocess the shell runs itself has none, so reading `NAME_PID`
      is refused. `coproc_default_name_is_coproc`, `named_coproc_reads_and_writes_through_its_array`, and
      `coproc_of_a_real_program_ends_when_its_input_closes` (real `tr`, knsh only). Pending: a run
      against bash 5.2 itself (KNSH-109): `/bin/bash` 3.2 has no `coproc`, and bash's descriptor numbers are not
      confirmed.*
- [x] Quoted delimiters disable expansion in here-documents. *An unquoted body is expanded as double-quoted text
      (never split or globbed); `<<-` strips the tabs starting each line. `quoted_heredoc_delimiter_disables_expansion`,
      `heredoc_dash_strips_leading_tabs`, `here_document_bodies_strip_tabs_like_bash`, and the differential script.*
- [x] Every command started inside a process substitution or coproc passes through the decision hook. *Each runs in
      a copy of the shell, which starts every program through the same `CommandSpawner` (the seam KNSH-108 decides
      at); nothing forks. `commands_inside_process_substitution_are_decided` (process and command substitution),
      `coproc_default_name_is_coproc` (the coprocess's program is a spawner request).*

**Unit tests**
- `process_substitution_provides_dev_fd_path`
- `coproc_default_name_is_coproc`
- `quoted_heredoc_delimiter_disables_expansion`
- `heredoc_dash_strips_leading_tabs`
- `commands_inside_process_substitution_are_decided`
- Also (`knsh-interp` evaluator): `command_substitution_gives_output_split_and_globbed_as_bash`,
  `substitution_status_is_the_status_of_an_assignment`, `errexit_in_command_substitution_follows_inherit_errexit`,
  `command_substitution_of_a_redirection_reads_the_file`, `redirections_read_process_substitutions`,
  `named_coproc_reads_and_writes_through_its_array`, and the updated
  `unsupported_constructs_are_refused_before_anything_runs`; `substitutions_become_parts`,
  `here_document_bodies_strip_tabs_like_bash` (`word`); `coproc_is_read_with_the_option` (`knsh-bash`);
  `data_pipes_carry_data_until_every_writer_is_gone` (`knsh-platform` fakes).

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `substitution_and_here_document_script_matches_bash` (against
  `/bin/bash` 3.2, real programs: `$( )`, backticks, `$?`, `$(< file)`, `diff <( ) <( )`, `< <( )`, `exec 4< <( )`,
  here-documents quoted and unquoted, `<<-`, on functions, groups and numbered descriptors, `set -e`).
- `coproc_of_a_real_program_ends_when_its_input_closes` (same file, the interpreter alone with a real `tr`: the
  coprocess sees end of file once the shell closes `COPROC[1]`; expected output from bash 5.2's source, pending KNSH-109).

**Implementation notes (KNSH-105).** `knsh-bash` gains `ParseOptions::coproc`: with it `coproc [NAME] command` is a
`Command::Unsupported` node holding `CoprocParts`, so the classifier still treats it as opaque (decision 6); without
it the line stays refused. `backtick_text` exposes bash's un-escaping. In `knsh-interp`, substitutions are word parts
(`Part::Subst`) that the expander hands to the evaluator, which builds a subshell copy from the shell's parts while
the expansion holds its state (`Seed`); `$( )` runs on a thread of its own while the shell reads the pipe, bounded at
64 MiB; `<( )` and `>( )` run detached and their descriptors are closed after their command; coprocesses are
background jobs whose ends the descriptor table holds close-on-exec (`FdTable::set_private`). Here-documents are
read like here-strings, after expansion. `knsh-platform` fakes gain data-carrying pipes
(`FakeDescriptors::with_data_pipes`) and `ScriptedCommands::releasing_descriptors`. Known differences and refusals
are listed in [compatibility](../04-non-functional-requirements/compatibility.md). Pending: a run against bash 5.2
itself for `coproc` and the forms where 3.2 differs (KNSH-109); substitutions inside `[[ … ]]` and `(( … ))` (still
refused); fuzzing under libFuzzer (nightly, not run here).
