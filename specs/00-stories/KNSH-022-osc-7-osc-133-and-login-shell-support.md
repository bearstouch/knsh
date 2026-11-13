# KNSH-022 — OSC 7, OSC 133 and login shell support

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Human shell | L (5) | [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | `knsh` | NFR-COMPAT-10, NFR-COMPAT-08 |

**Description.** Merged from *OSC 7 and OSC 133* and *Login shell support*: they are done and validated together because both are validated in the same terminal integration test.

*OSC 7 and OSC 133.* As a terminal user, I want `knsh` to mark prompts, commands, output and exit codes, so that any
terminal supporting OSC 7 and OSC 133 can navigate and annotate commands.

*Login shell support.* As a user, I want to set `knsh` as my login shell with `chsh`, with login behaviour identical to my
hosted shell.

**Acceptance criteria**
*OSC 7 and OSC 133*

- [ ] OSC 7 reports the working directory as a `file://host/path` URL with percent-encoding, on start and on every
      directory change.
- [ ] OSC 133 `A` (prompt start), `B` (command start), `C` (output start) and `D;<exit>` (command end) are emitted in
      that order, for zsh and bash, whether or not recording is on.
- [ ] Sequences are written only when stdout is a terminal.

*Login shell support*

- [ ] `knsh` detects login invocation (`argv[0]` starting with `-`, or `-l`/`--login`) and starts the hosted shell
      as a login shell.
- [ ] A command `knsh shell install` (or documented steps) adds `knsh` to `/etc/shells` only after explicit user
      confirmation; it never edits `/etc/shells` silently.
- [ ] The hosted shell is chosen from user configuration, defaulting to zsh; an invalid choice falls back to
      `/bin/zsh` with a warning rather than leaving the user without a shell.

**Unit tests**
*OSC 7 and OSC 133*

- `osc7_percent_encodes_path` — encoding.
- `osc133_sequence_order_for_one_command` — ordering (hook output captured).
- `no_sequences_when_not_a_tty` — non-interactive safety.

*Login shell support*

- `login_invocation_starts_hosted_shell_as_login` — argv handling.
- `invalid_hosted_shell_falls_back_to_zsh` — never lock the user out.

**Notes**
*Login shell support*

— The hosted-shell configuration key is not specified; add it to the spec with KNSH-021's recording key.
