# KNSH-106 — POSIX mode

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Compatibility | M (3) | [KNSH-101](KNSH-101-core-builtins.md), [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** As a user of `sh` scripts, I want `knsh` started as `sh` or with `--posix` to behave like bash's
POSIX mode, so that POSIX scripts behave as they do with `/bin/sh` on macOS (bash in POSIX mode).

Scope: bash's documented POSIX-mode differences (special builtins errors are fatal, assignment before special
builtins persists, `echo` behaviour, function name rules, tilde rules, etc.). POSIX behaviour comes through bash's
POSIX mode, not as a separate dialect (NFR-COMPAT-02).

**Acceptance criteria**
- [x] Starting as `sh` (argv[0]) or with `--posix` or `set -o posix` enables POSIX mode. *`knsh_interp::posix_mode_requested`
      follows bash 5.2's `shell.c` (file name `sh`, also as a login shell, whatever the options; `--posix` among the
      leading long options; `-o posix`); the host then starts with `ShellState::with_posix_mode` (`POSIXLY_CORRECT=y`
      and bash's `posix_initialize`). `set -o posix`, `shopt -so posix`, `POSIXLY_CORRECT` in the environment or
      assigned by the script turn it on; `set +o posix` and `unset POSIXLY_CORRECT` off. `argv0_sh_enables_posix_mode`,
      `posix_flag_enables_posix_mode`, `set_o_posix_enables_posix_mode`, `start_up_enables_posix_mode`. The `knsh`
      front end does not run the native interpreter yet, so wiring the flag into a binary is left to the story that
      does.*
- [x] Every item in bash's POSIX-mode list that the bash test suite covers matches bash. *The bash 5.2 suite's
      POSIX-mode cases (`errors3.sub`, `errors4.sub`, `errors7.sub`, `errors8.sub`, `errors.tests` function names,
      `builtins.tests` and `ifs.tests` assignments before special builtins, `func3.sub`, `varenv12.sub`,
      `source5.sub`, `builtins7.sub`, `tilde.tests`, `tilde3.sub`, `redir.tests`, `new-exp2.sub`, `set-e1.sub`) are
      unit tests with the `.right` outputs; `posixexp.tests`' single quotes in double-quoted `${…}`, which the parser
      would read differently, are refused (`Unsupported::PosixMode`), not matched. Checked against macOS `/bin/sh`
      (bash 3.2 `--posix`) where it agrees with 5.2: `posix_mode_script_matches_bash_posix`. Running the bash test
      suite itself against bash 5.2 is KNSH-109 (pending); what 3.2 and 5.2 do differently is listed in
      [compatibility](../04-non-functional-requirements/compatibility.md).*
- [x] No separate POSIX dialect code path: POSIX mode is a set of flags on the same interpreter.
      *`ShellOptions::posix` (with `shift_verbose`, `inherit_errexit`, `expand_aliases` and `.`'s working-directory
      search) is read where bash 5.2 reads `posixly_correct`; the parser and evaluator are the same.*

**Unit tests**
- `argv0_sh_enables_posix_mode`
- `posix_flag_enables_posix_mode`
- `special_builtin_error_is_fatal_in_posix_mode`
- `assignment_before_special_builtin_persists`
- Also (`knsh-interp` evaluator, `eval::tests::posix`): `assignment_errors_follow_posix_mode`,
  `function_names_follow_posix_rules`, `special_builtins_are_found_before_functions`, `source_follows_posix_mode`,
  `eval_syntax_errors_are_fatal_in_posix_mode`, `expansion_errors_are_fatal_in_posix_mode`,
  `tilde_follows_posix_mode`, `redirection_words_follow_posix_mode`, `echo_follows_macos_sh`,
  `set_o_posix_enables_posix_mode`, `start_up_enables_posix_mode`,
  `command_substitution_inherits_errexit_in_posix_mode`, `listings_follow_posix_mode`,
  `shift_and_loop_builtins_follow_posix_mode`, `command_keeps_declaration_words_in_posix_mode`,
  `posix_quotes_in_braces_are_refused`, `hashed_program_is_searched_again_in_posix_mode`,
  `nested_usage_error_is_not_the_special_builtins`, `bad_assignment_in_export_is_fatal_in_posix_mode`,
  `posix_variable_before_function_call_lasts_for_the_call`; updated
  `literal_refusals` (`options`), `forms_follow_bash` (`trap`), `job_lines_match_bash` (`jobs`),
  `alias_names_follow_bash` (`alias`), `unsupported_constructs_are_refused_before_anything_runs`.

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `posix_mode_script_matches_bash_posix` (against
  `/bin/bash --posix`, 3.2: assignments before special builtins, `alias`, `trap` and `export -p` listings, tilde
  and redirection words, `echo`, `break`, `POSIXLY_CORRECT`, `command`, `set +o posix`, a fatal usage error).

**Implementation notes (KNSH-106).** `crate::eval::posix` holds the special-builtin dispatch (found before
functions, assignments kept with `ShellState::set_special_temporary`, a usage error flagged by the builtin ending a
non-interactive shell unless tested). The other differences sit where bash makes them: `function` (names),
`nested` (`.` and `eval`), `expand` (fatal errors, tilde, redirection words), `control` (`echo`, `shift`, `break`),
`traps`, `alias`, `declare` (`export -p`), `builtins` (`type`, hash), `cd` and `jobs`. `echo` follows macOS's
`/bin/sh` ([decision 22](../09-reference/decisions.md)). Pending: a run against bash 5.2 itself (KNSH-109), where
3.2 differs; the parser's POSIX-mode reading of `${…}`, `time -` and reserved words (refused or default).
