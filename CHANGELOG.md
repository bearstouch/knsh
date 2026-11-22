# Changelog

All notable changes to Kinetic Shell (`knsh`) are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-22

The first versioned release, for macOS 14 and later on Apple silicon.

> [!WARNING]
> This build is labelled **advisory**: it gives **no security guarantees** and is **not for running agents
> unattended**. `knsh --version` and the `hello` handshake say the same.

### Added

- **Human shell.** `knsh` hosts your own zsh or bash unchanged. It emits OSC 7 and OSC 133 terminal marks and works
  as a login shell. Recording of human sessions is opt-in.
- **Daemon and CLI.** `knshd` runs as a per-user launchd agent. It keeps a record store and an event bus. You use
  them through `knsh history`, `events`, `forget`, `daemon install` and `shell install`, and every command takes
  `--json`.
- **Agent supervision.** Agent lines are classified by an in-house bash parser and decided by signed policy. They run
  in deny-by-default Seatbelt sandboxes through the `knsh-exec` trampoline. A network proxy applies host rules,
  address checks and TLS server-name checks.
- **Decisions.** An external, code-signed authority decides over XPC. Local approvals, grants with Touch ID, hooks and
  rate limiting of repeated denials are supported. `knsh agent` starts an agent CLI in an envelope, with presets for
  Claude Code and Codex CLI.
- **Undo.** APFS checkpoints capture what a line changes, with `knsh undo`, `redo` and `checkpoints`.
- **Secrets.** Secrets come from the Keychain or the authority. They are redacted on every output path, and a line
  that receives a secret has its network narrowed.
- **Irreversible actions.** They are flagged, need approval, and are reported on undo.
- **Native interpreter.** `knsh`'s own bash 5.2 interpreter, including bash's POSIX mode. In native mode every
  simple command of an agent line is decided, including inside scripts and functions. Humans can opt in with
  `[shell] hosted = "native"`.
- **Conformance gate.** It measures native mode against bash 5.2 and is enforced on release tags.
  - 234 of 235 agent commands (99.57%) behave as in bash.
  - 1800 of 2326 Oils spec cases (77.38%) pass.
  - 18 of 83 bash test-suite drivers (21.68%) pass.

### Fixed

- A native-mode agent line that the interpreter could not finish exited 0. It now exits 1 and still runs its
  `EXIT` trap.
- `"${a[@]}"` of an unset array now expands to no word, as in bash.
- Several CI tests that flaked on GitHub's macOS runners.

### Security

- `libc` is the only third-party runtime crate, vendored and exactly pinned. Builds run offline.
- Engine paths and control sockets are denied in every sandbox profile.
- Agent decisions fail closed; a human session is never blocked.

### Known limitations

- **Advisory.** Some performance targets are missed: the supervised line overhead, and checkpoints of very large
  trees. Touch ID, notarization and older macOS versions are not verified yet.
- **Native mode.** Variables bash maintains itself (`EPOCHSECONDS`, `RANDOM`, …) and the `kill` builtin are
  refused, and native sessions are not recorded yet.
- **macOS only.** Linux support is planned.

[0.1.0]: https://github.com/bearstouch/knsh/releases/tag/v0.1.0
