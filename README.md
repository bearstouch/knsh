# Kinetic Shell (`knsh`)

[![CI](https://github.com/bearstouch/knsh/actions/workflows/ci.yml/badge.svg)](https://github.com/bearstouch/knsh/actions/workflows/ci.yml)

A bash/zsh-compatible shell that lets AI agents run commands under recording, policy, operating-system sandboxing and best-effort undo. The engine provides mechanisms only: it records, enforces and reports; an external, code-signed **authority** decides and presents. macOS first (14+), Linux later.

| Binary | Role |
| --- | --- |
| `knsh` | Human shell (integration mode around stock zsh or bash), in-envelope agent client and CLI |
| `knshd` | Per-user daemon and supervisor, started on demand by launchd |
| `knsh-exec` | Single-threaded sandbox trampoline: applies a Seatbelt profile, then execs |

## Features

See the [user guide](docs/index.md) for how to use each feature, and [CHANGELOG.md](CHANGELOG.md) for what each version added.

Highlights:

- **Integration mode:** `knsh` hosts your own zsh or bash unchanged, with no dotfile edits. It picks the shell named by `[shell] hosted`, else your `$SHELL` if it is bash, else zsh, and starts it as a login shell when invoked as one (`-l`, `--login`, `-knsh`). OSC 7 and OSC 133 marks let terminals track directories and prompts.
- **Recording and records:** with `[recording] human = true`, human command lines are recorded by `knshd` (system SQLite, redaction at write time, retention), and `knsh history`, `knsh events` and `knsh forget` query, stream and delete them.
- **Agents in envelopes:** `knsh agent` starts an agent CLI (presets for Claude Code and Codex CLI) in a Seatbelt envelope. Each line is parsed, checked against signed policy, decided by the authority or a local approval, and run by the supervisor through `knsh-exec`; network traffic goes through the proxy.
- **Undo:** APFS checkpoints capture what each agent line changes; `knsh undo`, `knsh redo` and `knsh checkpoints` move between states, and irreversible actions such as `git push` are flagged for approval before they run.
- **Approvals and grants:** `knsh approvals`, `approve` and `deny`, time-limited grants with Touch ID, signed policy edited with `knsh policy edit`, and hooks that check every agent line.
- **Secrets:** from the Keychain or the authority, injected per command and redacted on every output path.
- **Native mode:** `[shell] hosted = "native"` runs `knsh`'s own bash 5.2 interpreter; agent lines in native mode are decided per simple command. A conformance gate measures it against bash 5.2 (99.57% of the agent-command corpus).
- **Fast start-up:** under 9 ms added to the first prompt at p95 on an M1 Pro, against a 50 ms target ([performance validation](specs/07-testing/performance-validation.md)).
- **Minimal supply chain:** one third-party runtime crate (`libc`), vendored and exactly pinned. JSON, TOML, the frame codec, CLI parsing and the SQLite binding are written in-house, and every parser is fuzzed.

Not implemented yet: `knsh run` and `knsh policy check` say so and exit with 1. Planned: Linux support (Landlock and seccomp), command introspection, an MCP client, session replay and optional structured pipelines.

## Documentation

The user guide is in [`docs/`](docs/index.md) and is built into static HTML for the website:

```sh
scripts/build-docs.sh               # builds site-docs/ (needs python3)
.venv-docs/bin/mkdocs serve         # live preview at http://127.0.0.1:8000/
```

Writing rules for the guide are in [`docs-theme/README.md`](docs-theme/README.md).

## Quick start

```sh
git clone https://github.com/bearstouch/knsh.git
cd knsh
cargo build --workspace --offline --locked
target/debug/knsh --version        # version banner, then the advisory label
target/debug/knsh                  # your zsh or bash, hosted by knsh
```

To record your sessions, install the daemon and turn recording on:

```sh
target/debug/knsh daemon install   # uses the knshd next to this knsh
mkdir -p ~/.config/knsh
printf '[recording]\nhuman = true\n' >> ~/.config/knsh/config.toml
target/debug/knsh                  # KNSH_RECORDING=1 in this shell
target/debug/knsh history --limit 10
```

Remove the launch agent with `knsh daemon uninstall`; engine data is kept until you delete it (or use `knsh forget`).

To run an agent in a sandbox, see [Getting started](docs/getting-started.md).

## Development setup

### Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| macOS | 14 Sonoma or later | Development and CI run on Apple silicon |
| Rust | 1.99.0 (edition 2024) | Pinned in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it on first use, with `rustfmt` and `clippy` |
| Xcode or Command Line Tools | Any recent version | For the system linker and SDK. CI pins Xcode 16.4 on `macos-15` |
| `cargo-deny` | 0.20.2 | Optional locally, required by `scripts/check.sh deny`. `cargo install --locked cargo-deny@0.20.2` |
| Nightly Rust and `cargo-fuzz` | `nightly-2026-11-01`, 0.13.2 | Only for fuzzing. `cargo install --locked cargo-fuzz@0.13.2` |

Check your toolchain:

```sh
rustc --version        # rustc 1.99.0
cargo clippy --version
```

You don't need network access to build. Every dependency is vendored in [`vendor/`](vendor/) and [`.cargo/config.toml`](.cargo/config.toml) forces offline mode; `scripts/check.sh` even builds under a Seatbelt profile that refuses network connections, so a build script that tries to download anything fails.

### Editors

- **VS Code / Cursor:** install [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer). It picks up the workspace and the pinned toolchain.
- **RustRover / other IDEs:** open the repository root; `Cargo.toml` is the workspace manifest.

### Everyday commands

```sh
cargo build --workspace --offline --locked              # build (must stay warning-free)
cargo test --workspace --offline                        # all unit and integration tests
cargo test -p knsh-bash                                 # one crate
cargo fmt --all                                         # format in place
cargo fmt --all --check                                 # must print nothing
cargo clippy --workspace --all-targets -- -D warnings   # lint: must be clean
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps   # docs must build without warnings
```

Before every commit, run the same gates as CI:

```sh
scripts/check.sh            # fmt, clippy, build, doc, test, deny, in that order
scripts/check.sh fmt test   # only the named steps
```

### Running `knsh`

| Command | What it does |
| --- | --- |
| `target/debug/knsh` | Hosts your stock zsh or bash in integration mode |
| `target/debug/knsh -l` | The same, as a login shell |
| `target/debug/knsh -c '<line>'` | Not for your own commands: a non-interactive line is treated as an agent line, supervised under the locked-down built-in `unattended` profile (inside an envelope it follows the agent's profile) |
| `target/debug/knsh daemon install` / `uninstall` | Installs or removes the per-user `knshd` launch agent |
| `target/debug/knsh shell install` | Adds `knsh` to `/etc/shells` (after asking), so `chsh -s` accepts it |
| `target/debug/knsh <command> --help` | Options for any command |

Engine data lives in `~/Library/Application Support/knsh/` (`user.sock` is under `run/`), and your settings in `~/.config/knsh/`. Both are owner-only (directories 0700, files 0600). Tests never touch them: they use temp dirs and an isolated state directory.

### Using the CLI

`knsh history`, `knsh events` and `knsh forget` talk to `knshd` over `user.sock`, so the daemon must be installed. A few examples:

```sh
knsh history --since 2026-11-14 --text cargo --limit 20
knsh history --session <id> --json
knsh events                                   # stream until Ctrl-C
knsh events --session <id> --since 42         # replay buffered events after seq 42, then stream
knsh forget --session <id>
knsh forget --since 2026-11-01 --with-checkpoints
```

The protocol (strict JSON-RPC over length-prefixed frames) is documented in [`specs/06-api`](specs/06-api/README.md) and the CLI in [`specs/06-api/cli.md`](specs/06-api/cli.md).

### Other scripts

```sh
scripts/startup-bench.sh                 # first-prompt time, plain zsh vs knsh-hosted zsh (NFR-PERF-04); results in .build/startup-bench/
scripts/fuzz.sh                          # every fuzz target, 60 s each (the CI smoke run)
scripts/fuzz.sh 600 json_reader          # one target, 10 minutes
cargo +nightly fuzz run toml_parser      # open-ended local run that grows the corpus (fuzz/README.md)
```

Fuzz targets: `json_reader`, `json_writer_roundtrip`, `frame_reader` and `toml_parser`. A crash saved under `fuzz/artifacts/` becomes a regression by copying it into `fuzz/regressions/<target>/`, which `cargo test` replays on stable.

### Workspace layout

Each crate has one concern, and dependencies point downwards only (binaries → services → core and parsers), enforced by `xtask/tests/dependency_policy.rs`.

| Crate | Role |
| --- | --- |
| `knsh-core` | Pure domain: sessions, records, events, policy model and evaluation, grants. No I/O |
| `knsh-bash` | In-house bash parser and classifier; anything it cannot read is classified as dynamic |
| `knsh-json` | Strict JSON (I-JSON) reader and writer, plus the frame codec |
| `knsh-toml` | Parser for the TOML subset used by policy and configuration |
| `knsh-proto` | JSON-RPC params and results, error codes, the capability model |
| `knsh-platform` | Platform traits and the macOS backend (launchd, Keychain, FSEvents, APFS, SQLite FFI, …) |
| `knsh-sandbox` | Compiles policy into Seatbelt profile text, as a pure function |
| `knsh-proxy` | HTTP CONNECT and SOCKS proxy, TLS server-name checks |
| `knsh-store` | Record store, retention, redaction at write time |
| `knsh-checkpoint` | Shadows, capture, history tree, restore rules |
| `knsh-interp` | Native bash 5.2 interpreter: walks the `knsh-bash` tree, runs commands through platform traits |
| `knshd`, `knsh`, `knsh-exec` | The three binaries; thin, with logic in the libraries |

`spikes/` holds throwaway prototypes that verify platform claims (Seatbelt behaviour, code-signed identity). They are not built by Cargo or shipped; their results are written up in [verification claims](specs/07-testing/verification-claims.md).

### CI

[`ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on a pinned `macos-15` Apple silicon runner with Xcode 16.4. Each job step calls `scripts/check.sh <step>`, so CI and local runs cannot drift apart: format, clippy, an offline no-network build with `-D warnings`, docs, tests, and `cargo deny` (licences, advisories, duplicate versions). No step may fail.

The current version is **0.1.0**; what each version changed is in the [changelog](CHANGELOG.md). Builds stay labelled advisory until the release gates in the [roadmap](specs/01-overview/roadmap.md) are met.

## Specification

The [`specs/`](specs/README.md) folder is the contract: the specs override assumptions, and a behaviour change updates the spec first. Requirements carry stable IDs (`FR-<AREA>-NN`, `NFR-<AREA>-NN`) that code comments, tests and commits cite.

Good starting points:

- [Introduction](specs/01-overview/introduction.md), [design principles](specs/01-overview/design-principles.md) and the [roadmap](specs/01-overview/roadmap.md)
- [System overview](specs/02-architecture/system-overview.md) and the [enforcement model](specs/02-architecture/enforcement-model.md)
- [Security and threat model](specs/04-non-functional-requirements/security.md) and the [supply-chain policy](specs/04-non-functional-requirements/supply-chain.md)
- [Implementation stories](specs/00-stories/README.md), one per pull request (`KNSH-NNN`)
- [Decisions](specs/09-reference/decisions.md) and [verification claims](specs/07-testing/verification-claims.md) still to confirm on real hardware

## Troubleshooting

- **`knsh history` says it cannot reach `knshd`:** install the launch agent with `knsh daemon install`. It must find a `knshd` binary next to the `knsh` you run, so use both from the same `target/` directory.
- **Nothing is recorded:** check that `~/.config/knsh/config.toml` has `[recording]` / `human = true` and that `echo $KNSH_RECORDING` prints `1` in the hosted shell.
- **`knsh daemon install` refuses under `sudo`:** this is intended. `knshd` runs as the logged-in user, never root.
- **The build tries to reach the network:** it shouldn't. Make sure you didn't bypass `.cargo/config.toml`, and that new dependencies are vendored with `cargo vendor`.
- **Clippy or rustdoc fails on a newer Rust:** the toolchain is pinned so new lints can't break the build. Use the version in `rust-toolchain.toml`.

## Contributing

Read [CLAUDE.md](CLAUDE.md) for the contributor rules: workspace layout, the dependency policy (`libc` is the only runtime crate; a new one needs a written justification), architecture rules (fail closed for agents, open for humans), code style, inline-documentation and test requirements, and the change workflow. Commits follow Conventional Commits with a crate or area as the scope, for example `feat(knsh-bash): …`.

Acceptance checks stay unchecked unless actually observed; platform checks that can't run in CI are recorded as **pending**, never as passed.

## License

Kinetic Shell is released under the [MIT License](LICENSE). Vendored dependencies keep their own licences, checked by `cargo deny` against [`deny.toml`](deny.toml).
