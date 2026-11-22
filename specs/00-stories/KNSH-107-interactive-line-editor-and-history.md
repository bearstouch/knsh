# KNSH-107 — Interactive line editor and history

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Interactive | XL (8) | [KNSH-101](KNSH-101-core-builtins.md) | `knsh` (binary), `knsh-interp` | NFR-COMPAT-02, NFR-COMPAT-06, NFR-COMPAT-10, NFR-PERF-04 |

**Description.** As a human using native mode, I want an interactive prompt with line editing, history and
completion close to bash's readline, so that I can choose native mode for daily use. zsh users stay in integration
mode (NFR-COMPAT-06).

Scope: in-house line editor (no readline/rustyline crates, per the dependency policy): emacs keybindings, vi mode
basics, UTF-8 and wide-character cursor movement, history file with `HISTFILE`, `HISTSIZE`, `HISTCONTROL`,
history expansion (`!!`, `!$`, `!n`), `PS1`/`PS2` expansion with bash escapes, programmable completion (`complete`,
`compgen`) basics, `.bashrc` loading as bash does, OSC 7 and OSC 133 marks.

Out of scope: full `.inputrc` support (flag as follow-up).

**Acceptance criteria**
- [x] Prompt escapes in `PS1` match bash. *`knsh_interp::interactive::prompt::decode` implements every escape of
      bash 5.2's `decode_prompt_string` (`\a \d \D{…} \e \h \H \j \l \n \r \s \t \T \@ \A \u \v \V \w \W \! \# \$
      \nnn \\ \[ \]`, `PROMPT_DIRTRIM`); with `promptvars` the result is expanded as an unquoted here-document
      (`Interpreter::expand_prompt`), escape results quoted first as bash quotes them. `ps1_escapes_expand_like_bash`,
      `working_directory_follows_home_and_dirtrim`, `promptvars_quotes_what_escapes_produce`,
      `prompts_are_expanded_as_here_documents`, `prompt_escapes_reach_the_terminal`. The PTY test uses `PS1='$ '`, so
      the escapes are checked against bash's documented results and source, not on a live bash screen.*
- [x] Cursor movement is correct for multi-byte and wide characters. *The cursor is a byte offset on a cell boundary
      (`interactive::line`): left and right step over a character and its zero-width followers together (readline's
      `MB_FIND_NONZERO`); `interactive::width` gives `wcwidth`'s 0, 1 or 2 columns; `interactive::render` places wide
      characters as the terminal wraps them. `cursor_moves_over_wide_characters`, `cursor_steps_over_whole_cells`,
      and the PTY test's `日本語` and `e\u{301}` lines match bash's screen.*
- [x] History expansion matches bash for the supported forms; unsupported forms are reported, not mis-expanded.
      *`interactive::expansion`: events `!! !n !-n !str !?str? !# ^a^b`, word designators, modifiers
      `h t r e p q x s & g a`, bash's quoting rules and messages (`!x: event not found`, `:9: bad word specifier`,
      `:s^a^b: substitution failed`, `:z: unrecognized history modifier`), checked against `bash -i` 3.2;
      `:G` is reported (`history expansion form not supported`). Expanded lines are shown before they run; `:p`
      shows and saves only. `history_expansion_bang_bang`, `events_and_words_match_bash`, `modifiers_match_bash`,
      `quoted_and_literal_bangs_are_kept`, `history_expansion_in_the_session`, PTY test `!$ !^`.*
- [x] Start-up time added to a session stays under 50 ms (NFR-PERF-04). *Measured on this machine (release build,
      macOS, 20 runs under a pseudo-terminal, empty `~/.bashrc` setting `PS1`, no history file): from spawn to the
      first prompt, native `knsh` median 7.2 ms (worst 15.6 ms) against `/bin/bash -i` 3.6–3.8 ms, so about 3.5 ms
      added. Not yet part of the KNSH-024 start-up benchmark.*
- [x] OSC 133 marks prompt, command, output and exit code (NFR-COMPAT-10). *`D;<exit>`, OSC 7 and `A` before each
      prompt, `B` once after it, `C` before the line runs, with the bytes of integration mode; only when `knsh`'s
      standard output is a terminal. `osc_133_marks_around_command`, `marks_are_osc_133`.*
- [x] Human sessions are never blocked or decided (FR-SES-22). *Native mode starts commands through the platform
      spawner with no supervisor in the way; refused constructs, failed expansions, syntax errors and unreadable
      history files are reported and the session goes on (`exit_ends_the_session_and_refusals_do_not`); the shell
      ignores the keyboard's signals itself and reads Ctrl-C as a key while editing. Native mode is opt-in
      (`[shell] hosted = "native"`) until KNSH-109 is green.*

**Unit tests**
- `ps1_escapes_expand_like_bash`
- `cursor_moves_over_wide_characters`
- `history_expansion_bang_bang`
- `histcontrol_ignoredups`
- `completion_lists_matching_commands`
- `osc_133_marks_around_command`
- Also (`knsh-interp`): `interactive::{width, keys, line, editor, render, history, expansion, prompt, complete,
  startup, marks, session}` tests (`emacs_keys_edit_like_readline`, `kill_ring_appends_consecutive_kills_and_cycles`,
  `history_walk_and_last_argument`, `reverse_search_finds_older_lines`, `vi_mode_basics`, `bytes_become_keys`,
  `specifications_print_like_bash`, `words_end_at_breaks_and_open_quotes`, `listing_and_common_prefix`,
  `startup_files_follow_bash`, `continuation_lines_use_ps2_and_join_in_the_history`, `tab_completes_and_lists`,
  `history_file_is_loaded_and_saved`, …) and `eval::tests::interactive` (`complete_and_compgen_builtins_match_bash`,
  `history_builtin_matches_bash`, `history_file_is_written_and_read_owner_only`, `lines_typed_at_the_prompt`,
  `interactive_messages_have_no_line_number`, `editing_modes_follow_set_o`); `knsh`:
  `native_mode_is_always_usable`, `hosted_shell_setting_accepts_only_zsh_or_bash`; `knsh-platform`:
  `host_has_a_name_and_a_pipe_has_no_terminal_name`, `user_names_come_from_the_user_database`.

**Integration tests**
- PTY-driven sessions comparing screen output with bash for a set of editing scripts:
  `crates/knsh/tests/native_editing.rs` `editing_matches_bash` (movement, wide and combining characters, kills and
  yank, history recall, history expansion, transpose, a wrapped line, incremental search, directory completion,
  Ctrl-C, vi mode), rendered by a small VT100 emulator and compared row by row with `/bin/bash` 3.2's screen.

**Notes.** Interactive behaviour is mostly outside the bash test suite; acceptance relies on PTY tests. Real IME and
keyboard layouts are manual checks — record as **pending**.

**Implementation notes (KNSH-107).** The editor, renderer, history, history expansion, prompt decoding and completion
model are pure modules of `knsh_interp::interactive`; `interactive::session` drives them over a `Terminal`
(`DescriptorTerminal` on the real one, through two new `Descriptors` calls: `set_editor_input` and
`terminal_columns`). The interpreter side (`eval::interactive`) runs typed lines (`Interpreter::run_line`, which says
when more lines are needed), expands prompts, generates completions and holds the `history`, `complete` and `compgen`
builtins; the history list and completion specifications live in `ShellState`, shared with subshell copies until
changed. `set -o emacs`, `vi`, `history`, `histexpand` and `shopt histappend`, `lithist` are now `ShellOptions` fields
(they were refused in an interactive shell). An interactive shell's messages carry no `line N:`, as bash's.
`knsh::native` builds the real shell for `[shell] hosted = "native"` ([terminals and
shells](../08-integrations/terminals-and-shells.md#native-mode-knsh-107), [decision 23](../09-reference/decisions.md)).
Out of scope or follow-ups: `.inputrc` and `bind`; `fc`; `history -n`; `HISTIGNORE`, `HISTTIMEFORMAT`; `compopt`;
`complete -C`, `-G` and the user, group, host and service actions; `--norc`, `--noprofile`, `--rcfile`; recording
a native session's telemetry; Ctrl-C interrupting a loop the shell runs itself; `IGNOREEOF`. Pending: real IME and
keyboard layouts (manual); a bash 5.2 run of the PTY scripts (only `/bin/bash` 3.2 here).
