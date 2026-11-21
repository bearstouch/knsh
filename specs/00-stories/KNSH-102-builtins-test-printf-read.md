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
- [x] `test` follows POSIX argument-count disambiguation exactly like bash. *`test_argument_count_rules` gives every
      count from none to more than four (with `!`, parentheses, `-a`/`-o` and the syntax errors' messages and status
      2), each checked against `/bin/bash` 3.2; `test_printf_read_script_matches_bash` runs them under the interpreter
      and `/bin/bash` and compares. Bash 3.2 differs from 5.2's `test.c` for `[ ! ! a ]` (too many arguments); 5.2
      is followed ([compatibility](../04-non-functional-requirements/compatibility.md)).*
- [x] `[[ =~ ]]` uses POSIX extended regular expressions as bash does, with an in-house or system regex engine
      (no new crate without justification). *The system's `regcomp(REG_EXTENDED)` and `regexec`, as bash calls them,
      in the shell's locale on the calling thread only ([decision 21](../09-reference/decisions.md)); no new crate.
      `regex_match_sets_bash_rematch`, `regex_follows_the_shell_locale` and the differential script; `BASH_REMATCH`
      is read as `PIPESTATUS` is until arrays exist (KNSH-103). Pending: the Linux `regex_t` layout (Linux backend).*
- [x] `printf` reuses its format for extra arguments, as bash does. *`printf_reuses_format_for_extra_args` and the
      differential script (a pass that consumes no argument is not repeated; missing arguments are empty or 0).*
- [x] `read -t` timeout returns status > 128. *142 (`128 + SIGALRM`, bash's), with what was read assigned:
      `read_timeout_status_above_128` over input that never ends; the real backend's wait is `poll`
      (`reads_wait_and_stat_descriptors`).*

**Unit tests**
- `test_argument_count_rules`
- `double_bracket_does_not_split_words`
- `regex_match_sets_bash_rematch`
- `printf_reuses_format_for_extra_args`
- `printf_q_quotes_for_reuse`
- `read_raw_keeps_backslashes`
- `read_timeout_status_above_128`
- Also: `file_tests_read_the_filesystem`, `variable_option_and_descriptor_tests`, `printf_builtin_assigns_quotes_and_reports`,
  `printf_time_uses_the_host_clock`, `read_splits_lines_like_bash`, `read_options_and_errors`,
  `read_prompts_and_sets_the_terminal`, `test_and_printf_run_in_the_shell` (`knsh-interp` evaluator);
  `numbers_format_like_the_c_library`, `number_errors_and_bad_conversions_are_bash_messages`, `escapes_and_strings`,
  `time_and_count_conversions`, `huge_fields_are_refused` (`printf` engine); `reads_bash_grammar`,
  `regex_words_gather_like_bash`, `syntax_errors_are_refused` (`[[` reader); `fields_split_like_bash`,
  `timeouts_read_like_uconvert` (`read`); `extended_expressions_match_with_subexpressions`,
  `locale_decides_multibyte_matching`, `formats_like_strftime_with_bash_buffer`, `reads_wait_and_stat_descriptors`,
  `status_and_access_serve_file_tests` (`knsh-platform`).

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `test_printf_read_script_matches_bash` (against `/bin/bash` 3.2).
- `crates/knsh-interp/tests/fuzz_regressions.rs`: the `builtin_conditional` fuzz target's seeds, saved crashes and
  hostile inputs (deep `[[`/`test` nesting, huge `printf` fields, endless `read` input).

**Notes.** Regex engine choice: macOS `regcomp`/`regexec` via `libc` keeps the dependency policy; Linux has the same
API. Decided and recorded in the crate docs and [decision 21](../09-reference/decisions.md).

**Implementation notes (KNSH-102).** `test`, `[`, `printf` and `read` are native builtins (the stand-ins that ran
`/bin/test` and `/usr/bin/printf` are gone). `[[ … ]]` stays opaque in the parser; the interpreter lexes its span
again with the same lexer (as it reads `(( … ))` bodies again) and reads it with bash 5.2's grammar, so operators are
recognised as written (`"-f"` is a word), the right side of `=~` keeps parentheses and `|`, and `==` reads extended
glob groups whatever `extglob` says. A `[[` bash's parser would reject is refused before anything runs, as is a
redirection after its `]]`. File tests go through `Fs::status` and `Fs::accessible` (`stat`/`lstat`,
`faccessat(AT_EACCESS)`); `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` are the shell's descriptor table,
stat'ed with `Descriptors::status`. `read` reads the shell's descriptor a byte at a time through
`Descriptors::read` (`Descriptors::wait_readable` for `-t`), and changes a terminal only through
`Descriptors::set_terminal_input`, putting it back however the read ends. The spawner's standard descriptors are
given by the host (`Interpreter::with_standard_descriptors`); without them reading or testing one is refused.
`printf` is a pure engine (`crate::printf`) formatting numbers as macOS's C library does; `%(…)T` uses the host's
`LocalTime` (`Interpreter::with_local_time`) and is refused without it or when the shell's `TZ` is not the zone the
host converts in. Limits: one `printf` field 1 MiB, one `printf` output 64 MiB, one `read` line 16 MiB
([defaults and limits](../09-reference/defaults-and-limits.md)). Refused until later stories: `read -a` (KNSH-103),
`read -e` on a terminal (KNSH-107), `nocasematch` for `[[` (KNSH-104). Pending: a run against bash 5.2 itself for the
5.2-only forms (KNSH-109); fuzzing `builtin_conditional` under libFuzzer (nightly, not run here).
