# KNSH-101 — Core builtins

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Builtins | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** As a script author, I want the commonly used bash builtins to behave like bash, so that scripts and
rc files run unchanged.

Scope: `cd` (with `CDPATH`, `-P`, `-L`, `OLDPWD`), `pwd`, `export`, `unset`, `readonly`, `declare`/`typeset`
(non-array attributes), `local` (scoping in 409), `shift`, `set` (positional parameters; options in 410), `exit`,
`return`, `break`, `continue`, `true`, `false`, `:`, `echo` (bash and `xpg_echo` behaviour), `eval`, `source`/`.`,
`command`, `builtin`, `type`, `hash`, `alias`/`unalias` (with `expand_aliases`), `umask`, `exec`.

**Acceptance criteria**
- [ ] Every listed builtin matches bash 5.2 for exit status, output and error message shape.
- [ ] `cd` emits OSC 7 after changing directory (NFR-COMPAT-10) and `cwd.changed` when recording.
- [ ] `eval` and `source` go through the same per-command decision path as any other command (KNSH-108).
- [ ] Aliases expand only when `expand_aliases` is on, as in bash (on in interactive mode).

**Unit tests**
- `cd_uses_cdpath_and_sets_oldpwd`
- `cd_physical_resolves_symlinks`
- `export_marks_variable_for_children`
- `readonly_blocks_assignment`
- `echo_escape_handling_matches_bash_and_xpg_echo`
- `return_outside_function_is_error`
- `alias_expansion_requires_expand_aliases`
- `type_reports_builtin_function_alias_file`
