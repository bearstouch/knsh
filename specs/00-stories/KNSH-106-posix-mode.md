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
- [ ] Starting as `sh` (argv[0]) or with `--posix` or `set -o posix` enables POSIX mode.
- [ ] Every item in bash's POSIX-mode list that the bash test suite covers matches bash.
- [ ] No separate POSIX dialect code path: POSIX mode is a set of flags on the same interpreter.

**Unit tests**
- `argv0_sh_enables_posix_mode`
- `posix_flag_enables_posix_mode`
- `special_builtin_error_is_fatal_in_posix_mode`
- `assignment_before_special_builtin_persists`
