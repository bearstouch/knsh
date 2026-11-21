# KNSH-104 — Traps, signals, `set` and `shopt` options

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Language | L (5) | [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md), [KNSH-101](KNSH-101-core-builtins.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02 |

**Description.** As a script author, I want traps, signal handling and shell options to match bash, so that cleanup
handlers and strict-mode scripts behave correctly.

Scope: `trap` for signals, `EXIT`, `ERR`, `DEBUG`, `RETURN`; signal disposition inheritance; `set -e` (with all of
bash's exceptions), `-u`, `-x` (`PS4`), `-o pipefail`, `-o noclobber`, `-f`, `-v`, `-n`; `shopt` options in scope
(`extglob`, `globstar`, `nullglob`, `failglob`, `dotglob`, `nocaseglob`, `lastpipe`, `expand_aliases`,
`inherit_errexit`, `xpg_echo`).

**Acceptance criteria**
- [x] `set -e` exceptions (conditions, `&&`/`||` lists, `!`, subshells with/without `inherit_errexit`) match bash.
      *A count of exempt contexts (bash's `CMD_IGNORE_RETURN`) covers `if`/`elif`/`while`/`until` conditions, every
      `&&`/`||` operand but the last, `!` pipelines and everything run inside them (functions, groups, subshells,
      which copy the count); a failing pipeline outside them runs `ERR` then exits; a compound command never exits
      by its own status, a function call or `( … )` does. `inherit_errexit` is held; subshells inherit `set -e`
      with or without it, as bash (the option acts on command substitution, KNSH-105).
      `errexit_ignored_in_conditions`, `errexit_in_subshell_respects_inherit_errexit`, and
      `traps_and_options_script_matches_bash` against `/bin/bash` 3.2. `[[ ]]`/`(( ))` exit as in bash 4.1 and later
      (3.2 exempts them): pending a run against bash 5.2 itself (KNSH-109).*
- [x] `EXIT` traps run once on normal exit, `exit`, and fatal signals that bash runs them for. *The trap is taken
      from the table as it runs; `$?` is the exit status (the last command's after a signal), a trap's `exit` decides
      the status; `set -e` and a subshell's own `EXIT` trap too; signals handed over by the host
      (`ShellSignals::raise`) at their default run it for bash's terminating signals (`SIGTERM`, `SIGHUP`, `SIGINT`,
      …) and not for `SIGQUIT`/`SIGPROF`, ending with 128 + n and `terminating_signal()`; an interactive shell runs it
      on `exit` or `Interpreter::finish`. `exit_trap_runs_once`, `signal_traps_run_between_commands`,
      `errexit_runs_the_exit_trap_like_bash` (3.2).*
- [x] `set -x` output format matches bash, including `PS4` expansion. *`PS4` decoded as a prompt and expanded as
      in double quotes (its own quotes kept), first character repeated per `eval`/`source` level; assignments on
      lines of their own, words quoted as `xtrace_print_word_list`; `for`/`case` heads, `(( ))` text, each `[[ ]]`
      term with pattern quoting. `xtrace_uses_ps4` (each line checked against 3.2) and the differential script;
      forms whose trace differs by version are refused or follow 5.2 (listed in compatibility).*
- [x] Ignored signals at entry stay ignored, as in bash. *The host gives them (`ShellState::with_ignored_signals`,
      read with `knsh_platform::macos::ignored_signals`); `trap` neither traps nor resets them in a non-interactive
      shell, the shell never acts on them, and every command starts with them (and `trap ''` signals) ignored through
      the new `ChildOptions::ignore`, applied in the child after any job-control reset.
      `ignored_signal_at_entry_stays_ignored`, `ignored_traps_reach_commands`, and in `knsh-platform`
      `ignored_signals_reach_the_child` (real processes) and `ignored_signals_never_include_kill`.*

**Unit tests**
- `errexit_ignored_in_conditions`
- `errexit_in_subshell_respects_inherit_errexit`
- `exit_trap_runs_once`
- `err_trap_runs_on_failure`
- `xtrace_uses_ps4`
- `ignored_signal_at_entry_stays_ignored`
- `shopt_unknown_option_is_error`
- Also (`knsh-interp` evaluator): `signal_traps_run_between_commands`, `debug_trap_runs_before_commands`,
  `return_trap_runs_as_functions_return`, `ignored_traps_reach_commands`, `trap_lists_and_changes_traps_like_bash`,
  `set_changes_and_lists_options_like_bash`, `shopt_lists_and_changes_options`, `noexec_and_verbose_follow_bash`,
  `traps_do_not_recurse_through_subshells`, `errexit_applies_inside_traps_fired_in_conditions`,
  `set_with_an_invalid_letter_changes_nothing`,
  and the updated `unsupported_constructs_are_refused_before_anything_runs`,
  `refusals_found_by_expansion_stop_the_script_there`; `listings_follow_bash_order`, `dash_flags_follow_bash_order`,
  `changes_are_refused_only_for_options_not_held`, `literal_refusals` (`options`); `decodes_specs_as_bash_trap_does`,
  `subshells_reset_traps_like_bash`, `hard_ignored_signals_cannot_be_trapped`, `pending_signals_are_taken_once`,
  `default_actions_follow_bash` (`trap`); `forms_follow_bash`, `signal_list_has_five_columns` (`trap` builtin);
  `prompts_decode_like_bash` (xtrace); `trace_words_are_quoted_like_xtrace` (`quote`);
  `names_are_in_increasing_order_of_number`, `signal_sets_hold_numbers_one_to_sixty_three`,
  `ignored_signals_never_include_kill`, `ignored_signals_reach_the_child` (`knsh-platform`).

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `traps_and_options_script_matches_bash` (against `/bin/bash` 3.2:
  `set -e` exemptions, `trap` listings, `DEBUG`, `ERR`, `RETURN`, `$-`, `set -o`, `shopt`, `set -x` traces with
  `PS4`, `set -n`) and `errexit_runs_the_exit_trap_like_bash`.

**Implementation notes (KNSH-104).** `set` (every letter and `-o` name of bash 5.2, `--`, `-`, `-o`/`+o` listings)
and `shopt` (`-pqsuo`) read and change `ShellOptions`, which gains `errexit`, `xtrace`, `verbose`, `noexec`,
`errtrace`, `functrace` and `inherit_errexit`; `crate::options` holds bash 5.2's whole `set -o` and `shopt` tables,
each option either implemented or fixed at bash's default (changing a fixed one is refused, before the script runs
when its words are literal); `$-` follows bash's letter order. `trap` (`-l`, `-p`, set, ignore, reset, numbers
first, bash's `decode_signal`) keeps a table in the shell state; a trap's text is parsed and checked when set (and
literal ones before the script runs). The evaluator runs `DEBUG` before simple commands, `for` iterations, `case`,
`[[ ]]`, `(( ))` and arithmetic `for` expressions (and as a traced function starts), `ERR` and `set -e` after a
failing pipeline outside exempt contexts, `RETURN` as functions and sourced files return, the pending signals after
each pipeline, and `EXIT` once when the shell or a subshell exits; functions and `source` set aside the traps they do
not inherit. Subshells reset traps as bash's `reset_signal_handlers`. `knsh-platform` gains `SignalSet`,
`ChildOptions::ignore` (set to `SIG_IGN` in the child before `exec`), `signals::NAMES` (bash's names, `trap -l`) and
`macos::ignored_signals`. `PS4` is set to `+ ` at start-up. Known differences and refusals are listed in
[compatibility](../04-non-functional-requirements/compatibility.md). Pending: a run against bash 5.2 itself for the
forms where 3.2 differs (KNSH-109); a host that catches signals and hands them over (the interpreter is not yet
embedded in a binary); fuzzing under libFuzzer (nightly, not run here).
