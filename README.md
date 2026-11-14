# Kinetic Shell (`knsh`)

> [!WARNING]
> **Phase 1 is advisory.** This build gives **no security guarantees** and is **not for running agents
> unattended**. It observes and records human shell sessions; it enforces nothing. `knsh --version` and the `hello`
> handshake (`advisory: true`) say the same. The first release that is safe to give to agents is phase 2
> ([roadmap](specs/01-overview/roadmap.md)).

Kinetic Shell is a bash/zsh-compatible shell that lets AI agents run commands under recording, policy,
operating-system sandboxing and best-effort undo. The engine provides mechanisms only: it records, enforces and
reports; an external, code-signed authority decides and presents. macOS first (14+), Linux later.

| Binary | Role |
| --- | --- |
| `knsh` | Human shell (integration mode around stock zsh or bash), in-envelope client and CLI |
| `knshd` | Per-user daemon and supervisor, started by launchd |
| `knsh-exec` | Single-threaded sandbox trampoline (phase 2) |

## What phase 1 does

- Hosts your own zsh or bash unchanged (integration mode), with OSC 7 / OSC 133 marks and login-shell support.
- Optionally records human command lines (`[recording] human = true` in `~/.config/knsh/config.toml`), shown by
  `KNSH_RECORDING=1` in the shell.
- Serves records and events on `user.sock`: `knsh history`, `knsh events`, `knsh forget`.

What it does **not** do yet: sandboxing, policy, approvals, the proxy, checkpoints or undo. Do not rely on it to
contain anything.

## Build and check

Rust stable (pinned in `rust-toolchain.toml`); dependencies are vendored, so everything builds offline.

```sh
cargo build --workspace --offline --locked
cargo test --workspace --offline
scripts/check.sh            # format, lint, build, docs, tests, dependency checks (as CI)
```

## Start-up benchmark

```sh
scripts/startup-bench.sh    # results in .build/startup-bench/
```

Times the first prompt of plain zsh and of `knsh`-hosted zsh (recording off and on) on a pseudo-terminal, against the
NFR-PERF-04 target (under 50 ms added at p95 on an Apple silicon Mac). Method and recorded results:
[performance validation](specs/07-testing/performance-validation.md).

## Specification

The specification is the contract: start at [specs/README.md](specs/README.md). Contributor guidance is in
[CLAUDE.md](CLAUDE.md).
