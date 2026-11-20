# KNSH-098 — Word splitting, quote removal and pathname expansion

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Expansion | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02 |

**Description.** As an agent, I want word splitting, brace expansion, globbing and quote removal to happen in bash's
order with bash's rules, so that file arguments and loops behave identically.

Scope: brace expansion (lists, sequences with step, zero padding), expansion order, `IFS` splitting (whitespace vs
non-whitespace delimiters, empty `IFS`, unset `IFS`), quote removal, pathname expansion (`* ? [...]`, character
classes, `dotglob`, `nullglob`, `failglob`, `nocaseglob`, `globstar`, `extglob` patterns), sorted results using the
locale rules bash uses. Directory listing goes through an injected filesystem trait.

**Acceptance criteria**
- [x] Expansion order matches bash: brace, tilde, parameter/arithmetic/command substitution, splitting, globbing,
      quote removal. *Command substitution is still refused (KNSH-100); the rest is compared with `/bin/bash`
      (`words_script_matches_bash`) and unit-tested (`expansion_order_matches_bash`).*
- [x] `IFS` edge cases match bash, including leading/trailing whitespace and consecutive non-whitespace delimiters.
      *Compared with `/bin/bash` 3.2, whose splitting rules bash 5.2 keeps; a run against bash 5.2 itself is
      pending (KNSH-109).*
- [x] Unmatched globs stay literal unless `nullglob`/`failglob` is set. *Compared with `/bin/bash -O nullglob` and
      `-O failglob` (`glob_options_match_bash`).*
- [ ] `extglob` and `globstar` behave as in bash 5.2 when enabled. *Implemented from bash 5.2's rules and
      unit-tested; `extglob` is also compared with `/bin/bash -O extglob`. Pending: bash 3.2 has no `globstar`, and
      only bash 3.2 is installed here, so neither is checked against bash 5.2 itself (KNSH-109).*
- [x] Sorting order of glob results matches bash in the C and UTF-8 locales used in CI. *Compared with `/bin/bash`
      under `LANG=C`, `C.UTF-8` and `en_US.UTF-8` on macOS (`glob_order_matches_bash_in_c_and_utf8_locales`);
      Linux (glibc) collation is pending (KNSH-110).*

**Unit tests**
- `brace_sequence_with_step_and_padding`
- `ifs_whitespace_and_nonwhitespace_delimiters`
- `empty_ifs_disables_splitting`
- `unmatched_glob_stays_literal`
- `nullglob_removes_unmatched_word`
- `failglob_reports_error`
- `dotglob_includes_hidden_files`
- `globstar_matches_recursively`
- `extglob_patterns_match_like_bash`

**Integration tests**

- `crates/knsh-interp/tests/bash_differential.rs`: `words_script_matches_bash`, `glob_options_match_bash`,
  `glob_order_matches_bash_in_c_and_utf8_locales` (against `/bin/bash`).
- Fuzz target `word_expansion` added to `fuzz/` (no panics, deterministic, bounded); seeds replayed on stable by
  `crates/knsh-interp/tests/fuzz_regressions.rs`.

**Implementation notes (KNSH-098).** Arguments and `for` items are brace-expanded first (`knsh-interp`'s `brace`,
a port of bash 5.2's `braces.c`), on the pieces of the word as written: quotes, escapes and expansions are opaque,
and their source text is what bash's rules look at (a `,` anywhere inside the braces makes a list; `{1..$n}` is not
a sequence). Each word produced is read again as bash reads it, so `$a{1,2}` is `$a1 $a2`; one whose pieces would
form `${…}`, `$(…)` or `$[…]` is refused. Then tilde, parameter and arithmetic expansion (KNSH-097), `IFS` splitting
(`expand::split`, bash's `list_string`), pathname expansion (`glob`) and quote removal. A quoted empty string in a
partly quoted word (`""$x`) is dropped before splitting, as bash drops it. An unquoted literal character that is in `IFS`
is quoted, as bash quotes it when it reads the word, so with `IFS='*'` a literal `*` matches no file name. `$'…'` is now decoded (cut at a NUL).

Pathname expansion reads directories only through `knsh_platform::Fs` (`list_dir`, `metadata`, `canonicalise`) and
follows bash 5.2: hidden names need a leading `.` (or `dotglob`), `.` and `..` never match (`globskipdots`), a
trailing `/` keeps directories, `**` with `globstar` does not follow symlinks or enter hidden directories,
`GLOBIGNORE` filters results and implies `dotglob` while set. Results are sorted with the new
`knsh_platform::Collation` (`newlocale` and `strcoll_l` on macOS, the locale from `LC_ALL`, `LC_COLLATE` or `LANG`,
ties by bytes; a locale the system lacks leaves the C order, as bash's failed `setlocale` does; a locale name holding
`/` or starting with `.` is never loaded). `Interpreter::new` takes the collation. A matching file name that is not
UTF-8 is refused (`Unsupported::NonUtf8FileName`).

Options: `set -f` and `shopt` options `dotglob`, `nullglob`, `failglob`, `nocaseglob`, `globstar`, `extglob` are
`ShellOptions` fields until the builtins arrive (KNSH-104); `$-` shows `f`. `failglob` reports `no match: word`
and abandons the rest of the line with status 1, as `bash -c` does, and wins over `nullglob`. With `extglob` the
groups apply in pathname expansion, `case` patterns and the `${…}` pattern operators, and a script using them in its
own text must be parsed with `knsh_bash::parse_with` and `ParseOptions::extglob` (bash reads a line with the options
set before it); the lexer then reads a group's parentheses as part of the word. The pattern matcher compiles a pattern
once; patterns with groups are matched by sets of end positions with memoised alternatives (polynomial; the memo holds at most 64 Mi end
positions and is emptied when full), and groups nest at most 64 deep.

Bounds (CLAUDE.md "Untrusted input", listed in [defaults and limits](../09-reference/defaults-and-limits.md)): brace
expansion of one word at most 1,048,576 words, 64 Mi characters and 64 Mi characters examined; pathname expansion at
most 1,048,576 entries per directory, 4,194,304 entries read and 1,048,576 matches per word. Past a bound the run
fails with `InterpError::ExpansionLimit`, before anything runs when the brace expansion is literal.

Known differences, listed in [compatibility](../04-non-functional-requirements/compatibility.md): in the C locale
bash matches `?` and brackets against bytes, the interpreter against characters (they differ only for non-ASCII
text); the `failglob` message shows the word after quote removal; dot-file rules for patterns that start with an
`extglob` group follow the leading group's alternatives, a simplification of bash 5.2's. Still refused: joining an
unquoted `$*` or `$@` with a non-space `IFS` where bash does not split (`Unsupported::UnsplitJoin`, settled against
bash 5.2 by KNSH-109).
