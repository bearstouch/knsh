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
- [ ] Expansion order matches bash: brace, tilde, parameter/arithmetic/command substitution, splitting, globbing,
      quote removal.
- [ ] `IFS` edge cases match bash, including leading/trailing whitespace and consecutive non-whitespace delimiters.
- [ ] Unmatched globs stay literal unless `nullglob`/`failglob` is set.
- [ ] `extglob` and `globstar` behave as in bash 5.2 when enabled.
- [ ] Sorting order of glob results matches bash in the C and UTF-8 locales used in CI.

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
