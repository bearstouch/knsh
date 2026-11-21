# KNSH-105 — Process substitution, `coproc` and here-documents

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Execution | M (3) | [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02, decision 6 |

**Description.** As a script author, I want `<( )`, `>( )`, `coproc` and here-documents to work as in bash, so that
advanced scripts run.

Scope: command substitution `$( )` and backquotes (moved here from KNSH-100: it captures a subshell's output as
process substitution does), process substitution via `/dev/fd/N`, `coproc` with named and default (`COPROC`) arrays,
here-documents with and without expansion, `<<-` tab stripping. In phase 2 these were classified as dynamic when fed to shells or
interpreters (decision 6); in native mode each command they run is decided individually (KNSH-108).

**Acceptance criteria**
- [ ] `$(cmd)` and `` `cmd` `` give the command's output without its trailing newlines, split and globbed as bash
      does, and `$?` after an assignment is the substitution's status.
- [ ] `diff <(a) <(b)` works and descriptors are closed after use.
- [ ] `coproc` exposes read/write descriptors and the PID like bash.
- [ ] Quoted delimiters disable expansion in here-documents.
- [ ] Every command started inside a process substitution or coproc passes through the decision hook.

**Unit tests**
- `process_substitution_provides_dev_fd_path`
- `coproc_default_name_is_coproc`
- `quoted_heredoc_delimiter_disables_expansion`
- `heredoc_dash_strips_leading_tabs`
- `commands_inside_process_substitution_are_decided`
