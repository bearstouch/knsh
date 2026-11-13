# KNSH-019 — Integration mode: hosting stock zsh

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Human shell | L (5) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md) | `knsh` | FR-SES-20, FR-SES-22, NFR-COMPAT-01, NFR-COMPAT-03, NFR-COMPAT-06, [terminals and shells](../08-integrations/terminals-and-shells.md) |

**Description.** As a zsh user, I want to run `knsh` and get my own zsh with all my rc files unchanged, plus
command observation hooks, so that I can opt into telemetry without changing shells. `knsh` starts stock zsh as a
child with a startup directory that first sources the user's real startup files in zsh's normal order, then adds
`preexec`/`precmd` functions (via `add-zsh-hook`, never replacing the user's hooks). The hooks write compact
telemetry lines to a descriptor inherited from `knsh`, which forwards them (KNSH-021). Nothing is blocked or
rewritten.

**Acceptance criteria**
- [ ] The user's `.zshenv`, `.zprofile`, `.zshrc`, `.zlogin` run in the same order and with the same `$ZDOTDIR`
      semantics as plain zsh; a test rc file that records its order produces the same trace under `knsh` and zsh.
- [ ] Existing `preexec`/`precmd` hooks of the user (and of frameworks such as oh-my-zsh) still run.
- [ ] If the telemetry descriptor is closed or `knsh`'s forwarder is gone, the hooks do nothing and never print
      errors or delay the prompt.
- [ ] Exit status, signals, job control and terminal ownership behave as in plain zsh; `knsh` exits with zsh's
      status.
- [ ] With recording off, no telemetry is produced and `knshd` is not contacted.

**Unit tests**
- `startup_wrapper_sources_user_files_in_zsh_order` — generated wrapper content.
- `hooks_are_added_not_replaced` — `add-zsh-hook` usage.
- `telemetry_line_encoding_round_trips` — the line format between hooks and `knsh`.

**Integration tests**
- Run `knsh` with a temp `HOME` and a recording test rc; compare traces with plain zsh.
- Close the telemetry descriptor mid-session; prompts continue with no output and no delay.

**Notes.** — The startup-file mechanism (custom `ZDOTDIR` restoring the user's value) is an implementation choice,
not in the spec; record it in [terminals and shells](../08-integrations/terminals-and-shells.md).
