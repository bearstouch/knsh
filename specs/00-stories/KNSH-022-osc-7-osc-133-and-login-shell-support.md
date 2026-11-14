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

- [x] OSC 7 reports the working directory as a `file://host/path` URL with percent-encoding, on start and on every
      directory change.
- [x] OSC 133 `A` (prompt start), `B` (command start), `C` (output start) and `D;<exit>` (command end) are emitted in
      that order, for zsh and bash, whether or not recording is on.
- [x] Sequences are written only when stdout is a terminal.

*Login shell support*

- [x] `knsh` detects login invocation (`argv[0]` starting with `-`, or `-l`/`--login`) and starts the hosted shell
      as a login shell.
- [ ] A command `knsh shell install` (or documented steps) adds `knsh` to `/etc/shells` only after explicit user
      confirmation; it never edits `/etc/shells` silently.
- [x] The hosted shell is chosen from user configuration, defaulting to zsh; an invalid choice falls back to
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
*OSC 7 and OSC 133*

— Implemented in the zsh and bash wrappers, which are now read whenever the marks are wanted, recording or not
(bash without recording previously ran with no file of `knsh`'s). Mechanism and limits:
[terminal markup](../08-integrations/terminals-and-shells.md#terminal-markup).

*Login shell support*

— Decided: `[shell] hosted` in `~/.config/knsh/config.toml`, next to KNSH-021's `[recording] human`
([login shell](../08-integrations/terminals-and-shells.md#login-shell)). Without it, the KNSH-020 rule applies
(the bash `$SHELL` names, else zsh), which is zsh once `knsh` is the login shell.

— `knsh shell install`: the flow (already listed, yes, no, no terminal, unrepresentable path, failed append) is
unit-tested with a fake, and the refusal without a terminal end to end. **Pending:** the real append through `sudo`
and `chsh -s` to `knsh` followed by a new login in Terminal.app need a manual check with an administrator password.

— **Known limit:** with `knsh` as the login shell, non-interactive login invocations (`ssh host cmd`, `scp`,
`rsync`, `$SHELL -l -c env`) fail until `knsh -c` is implemented (agent and unattended paths, later stories).
Documented in [CLI](../06-api/cli.md#login-shell) and printed by `knsh shell install`.
