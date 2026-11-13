# KNSH-099 — Redirections and descriptor management

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Execution | L (5) | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | `knsh-interp`, `knsh-platform` | NFR-COMPAT-02 |

**Description.** As a script author, I want every bash redirection to work, so that output, errors and descriptors
go where bash would send them.

Scope: `< > >> >| <> <& >& &> &>> 2>&1`, numbered descriptors, `{var}>` named descriptors, closing with `-`, `noclobber`,
`exec` with redirections only (persistent), here-strings `<<<`, `/dev/stdin`, `/dev/fd/N`, `/dev/tcp` (see notes),
save/restore of descriptors around builtins and functions. Descriptor effects go through `knsh-platform`.

**Acceptance criteria**
- [ ] Redirections are applied left to right as in bash (`2>&1 >file` vs `>file 2>&1`).
- [ ] `noclobber` blocks `>` on existing files and `>|` overrides it.
- [ ] Redirections on builtins and functions are undone after the command.
- [ ] `exec 3>file` persists for the shell; `exec 3>&-` closes it.
- [ ] Descriptors are not leaked to child processes beyond what bash passes.

**Unit tests**
- `redirection_order_matters_like_bash`
- `noclobber_blocks_overwrite`
- `force_clobber_overrides_noclobber`
- `builtin_redirection_is_restored`
- `exec_redirection_persists`
- `named_fd_assigns_variable`
- `here_string_appends_newline`
- `no_descriptor_leak_to_children`

**Notes.** `/dev/tcp` and `/dev/udp` open network connections from the shell itself. Inside a sandboxed line these
must still be confined by the profile and the proxy (FR-NET-08: no direct network). Decide in the spec whether
`/dev/tcp` is supported, refused, or routed — **spec gap, flag before implementing**.
