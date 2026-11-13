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
- [ ] Prompt escapes in `PS1` match bash.
- [ ] Cursor movement is correct for multi-byte and wide characters.
- [ ] History expansion matches bash for the supported forms; unsupported forms are reported, not mis-expanded.
- [ ] Start-up time added to a session stays under 50 ms (NFR-PERF-04).
- [ ] OSC 133 marks prompt, command, output and exit code (NFR-COMPAT-10).
- [ ] Human sessions are never blocked or decided (FR-SES-22).

**Unit tests**
- `ps1_escapes_expand_like_bash`
- `cursor_moves_over_wide_characters`
- `history_expansion_bang_bang`
- `histcontrol_ignoredups`
- `completion_lists_matching_commands`
- `osc_133_marks_around_command`

**Integration tests**
- PTY-driven sessions comparing screen output with bash for a set of editing scripts.

**Notes.** Interactive behaviour is mostly outside the bash test suite; acceptance relies on PTY tests. Real IME and
keyboard layouts are manual checks — record as **pending**.
