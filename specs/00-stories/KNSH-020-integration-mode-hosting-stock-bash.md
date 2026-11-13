# KNSH-020 — Integration mode: hosting stock bash

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Human shell | L (5) | [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | `knsh` | FR-SES-20, FR-SES-22, NFR-COMPAT-01, NFR-COMPAT-04 |

**Description.** As a bash user (including macOS bash 3.2), I want the same integration as zsh. bash has no native
`preexec`, so the hooks use the `DEBUG` trap plus `PROMPT_COMMAND`, chained with any the user already set. Startup
files must run as in plain bash for login and non-login interactive shells.

**Acceptance criteria**
- [ ] Works on `/bin/bash` 3.2 and Homebrew bash 5; the user's `.bash_profile`/`.bashrc`/`.profile` run as in plain
      bash for login and non-login shells.
- [ ] Existing `PROMPT_COMMAND` (string or, in bash 5.1+, array) and `DEBUG` traps of the user still run.
- [ ] One telemetry record per command line typed at the prompt, not one per simple command inside it, and none for
      the hooks' own commands.
- [ ] Hook failures are silent and never change `$?` seen by the user's prompt.

**Unit tests**
- `wrapper_chains_existing_prompt_command` — chaining.
- `debug_trap_fires_once_per_interactive_line` — de-duplication logic (pure helper).

**Integration tests**
- Run the same trace tests as KNSH-019 under bash 3.2 and bash 5; verify `$?` and `PIPESTATUS` are unchanged at
  the prompt.
