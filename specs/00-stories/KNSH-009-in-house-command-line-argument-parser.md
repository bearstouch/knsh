# KNSH-009 — In-house command-line argument parser

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | CLI | M (3) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `knsh` (module `cli::args`) | NFR-SUP-01 (no CLI crates), [CLI](../06-api/cli.md) |

**Description.** As a user, I want `knsh` subcommands with consistent flags and help, without a third-party CLI
crate. A small declarative parser: subcommands, long flags (`--json`, `--profile <p>`), short flags where bash needs
them (`-c`, `-i`, `-l`), `--` separator, and generated help. It must also recognise shell invocations
(`knsh`, `knsh -c '…'`, login shell `-knsh` / `-l`) without treating them as subcommands. Out of scope: the
subcommands' behaviour.

**Acceptance criteria**
- [ ] `knsh agent --profile web-app -- claude --flag` yields subcommand `agent`, option `profile`, and trailing argv
      `["claude", "--flag"]` untouched.
- [ ] Every subcommand accepts `--json`.
- [ ] Unknown flags and missing values produce an error naming the flag and exit with status 2; nothing runs.
- [ ] Shell-mode argv (`-c`, `-i`, `-l`, `argv[0]` starting with `-`) is classified before subcommand parsing.
- [ ] Help text is generated from the same declarations.

**Unit tests**
- `double_dash_passes_remaining_argv_unchanged` — `knsh agent`.
- `json_flag_accepted_by_every_subcommand` — CLI rule.
- `unknown_flag_is_error_and_runs_nothing` — fail safe.
- `dash_c_is_shell_mode_not_subcommand` — `knsh -c 'history'` runs a shell line, not `knsh history`.
- `login_argv0_dash_prefix_detected` — login shell.
