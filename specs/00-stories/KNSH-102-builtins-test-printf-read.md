# KNSH-102 — Builtins: `test`, `[[ ]]`, `printf`, `read`

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Builtins | L (5) | [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md), [KNSH-101](KNSH-101-core-builtins.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** As a script author, I want conditional tests, formatted output and input reading to match bash, so
that the most common script idioms work.

Scope: `test`/`[` (POSIX argument-count rules), `[[ ]]` (pattern matching, `=~` with `BASH_REMATCH`, no word
splitting), file tests, string and integer comparisons, `printf` (all bash format specifiers, `%q`, `%(fmt)T`, `-v`),
`read` (`-r -a -d -n -N -p -s -t -u`, `IFS` handling, timeouts).

**Acceptance criteria**
- [ ] `test` follows POSIX argument-count disambiguation exactly like bash.
- [ ] `[[ =~ ]]` uses POSIX extended regular expressions as bash does, with an in-house or system regex engine
      (no new crate without justification).
- [ ] `printf` reuses its format for extra arguments, as bash does.
- [ ] `read -t` timeout returns status > 128.

**Unit tests**
- `test_argument_count_rules`
- `double_bracket_does_not_split_words`
- `regex_match_sets_bash_rematch`
- `printf_reuses_format_for_extra_args`
- `printf_q_quotes_for_reuse`
- `read_raw_keeps_backslashes`
- `read_timeout_status_above_128`

**Notes.** Regex engine choice: macOS `regcomp`/`regexec` via `libc` keeps the dependency policy; Linux has the same
API. Decide and record in the crate docs.
