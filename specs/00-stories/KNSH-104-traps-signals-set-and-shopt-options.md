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
- [ ] `set -e` exceptions (conditions, `&&`/`||` lists, `!`, subshells with/without `inherit_errexit`) match bash.
- [ ] `EXIT` traps run once on normal exit, `exit`, and fatal signals that bash runs them for.
- [ ] `set -x` output format matches bash, including `PS4` expansion.
- [ ] Ignored signals at entry stay ignored, as in bash.

**Unit tests**
- `errexit_ignored_in_conditions`
- `errexit_in_subshell_respects_inherit_errexit`
- `exit_trap_runs_once`
- `err_trap_runs_on_failure`
- `xtrace_uses_ps4`
- `ignored_signal_at_entry_stays_ignored`
- `shopt_unknown_option_is_error`
