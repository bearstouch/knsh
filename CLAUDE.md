# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

**Kinetic Shell** (`knsh`) is a bash/zsh-compatible shell that lets AI agents run commands under recording, policy,
operating-system sandboxing and best-effort undo. The engine provides mechanisms only: it records, enforces and reports;
an external, code-signed **authority** decides and presents. macOS first (14+), Linux later.

Binaries: `knsh` (human shell, in-envelope client, CLI), `knshd` (per-user daemon and supervisor), `knsh-exec`
(single-threaded sandbox trampoline).

- **The specification is the contract:** `specs/` (start at `specs/README.md`). The specs override assumptions. If a
  page is ambiguous, fix the page; never invent behaviour that conflicts with it.
- Requirement IDs (`FR-<AREA>-NN`, `NFR-<AREA>-NN`) are stable. Reference them in code comments, tests and commits.
- Roadmap and phase gates: `specs/01-overview/roadmap.md`. Decisions: `specs/09-reference/decisions.md`. Platform
  claims still to verify: `specs/07-testing/verification-claims.md`.

## Toolchain and commands

Rust stable, edition 2024, pinned in `rust-toolchain.toml`. Cargo workspace; dependencies are vendored in `vendor/`, so
every build works with `--offline`.

```sh
cargo build --workspace --offline --locked              # must be warning-free
cargo test --workspace --offline --lib --bins          # normal suite: unit tests only (~2 min)
cargo test --workspace --offline                        # full suite: adds tests/ integration targets (on demand only)
cargo test -p knsh-bash --lib                           # one crate's unit tests
cargo fmt --all                                         # format (config: rustfmt.toml)
cargo fmt --all --check                                 # must print nothing
cargo clippy --workspace --all-targets -- -D warnings   # lint: must be clean
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps   # docs must build without warnings
cargo +nightly fuzz run <target>                        # fuzz a parser (fuzz/, test-only)
```

**Two test suites.** The **normal suite** (`--lib --bins`, unit tests next to the code) is the default: run it
while iterating and before every commit; it must finish within 5 minutes. The **full suite** (`cargo test
--workspace`) also runs each crate's `tests/` integration targets, which drive real APFS, FSEvents and processes
and take minutes (for example `knsh-checkpoint`'s `watch_macos` and `shadow_macos`). Run the full suite **only when
the user asks for it**; otherwise record it as not run (pending) in the commit or PR. While iterating, prefer the
changed crates' unit tests (`cargo test -p <crate> --lib`). Never start two cargo runs at once: they wait on the
same build lock. Known flake: `knshd` `hooks::tests::timeout_denies_and_kills_hook` can fail under full load;
rerun it alone before treating it as a regression.

Run format, lint, build, doc and the normal test suite before every commit. CI also runs licence, advisory and duplicate-version checks
(`cargo deny`). These tools are CI-only and never shipped.

## Workspace layout

Each crate has one concern. Dependencies point downwards only: binaries → services → core and parsers. No cycles.

| Crate | Role | Depends on |
| --- | --- | --- |
| `knsh-core` | Pure domain: sessions, records, events, policy model and evaluation, verdict combining, grants, rate limiting. No I/O. | parsers |
| `knsh-bash` | In-house bash parser and classifier (wrappers, dynamic code, irreversibility). Anything it cannot read is classified as dynamic. | — |
| `knsh-json` | Strict JSON (I-JSON profile) reader and writer, plus the length-prefixed frame codec. | — |
| `knsh-toml` | Parser for the TOML subset used by policy and configuration. | — |
| `knsh-proto` | JSON-RPC method params and results, the error codes, the capability model. | `knsh-json`, `knsh-core` |
| `knsh-platform` | The platform interface (traits) and the macOS backend: XPC, Keychain, LocalAuthentication, FSEvents, APFS clones, unified logging, CommonCrypto, SQLite FFI. | `knsh-core`, `knsh-json`, `libc` |
| `knsh-sandbox` | Compiles policy into Seatbelt profile text. Pure function: same input, same bytes. | `knsh-core` |
| `knsh-proxy` | HTTP CONNECT and SOCKS proxy, TLS server-name reader, host and address checks. | `knsh-core`, `knsh-platform` |
| `knsh-store` | Record store (system SQLite), retention, redaction at write time. | `knsh-core`, `knsh-platform` |
| `knsh-checkpoint` | Shadows, capture, post-image identity, history tree, restore rules. | `knsh-core`, `knsh-json`, `knsh-platform` |
| `knshd` | Daemon binary: endpoints, supervisor, event bus, wiring. Thin; logic lives in libraries. | all services |
| `knsh` | Shell front end (integration mode, native mode for humans), agent client, shims and CLI; the sandboxed interpreter of native-mode agent lines (`--native-line`, KNSH-108). | `knsh-proto`, `knsh-json`, `knsh-core` (IDs, timestamps), `knsh-platform` (engine paths, launchd agent, supervision channel), `knsh-toml` (user settings), `knsh-interp` (native mode, KNSH-107), `knsh-bash` (native-mode lines, KNSH-108) |
| `knsh-interp` | Native bash interpreter (phase 4): walks the `knsh-bash` tree, shell state, exit statuses; runs commands through `knsh-platform` traits (`CommandSpawner`, `Fs`); for agent lines, `knsh-platform`'s `SupervisedSpawner` asks the supervisor for each one (KNSH-108). | `knsh-bash`, `knsh-platform` |
| `knsh-exec` | Trampoline: applies a profile with `sandbox-exec -f`, then execs. **std only**, single-threaded, no workspace deps. | — |

The decision and enforcement path never leaves Rust. A Swift helper is allowed only for a macOS service that is
impractical to reach from Rust, behind the `knsh-platform` interface.

## Dependencies (minimal by design)

Every crate is code that runs with the user's privileges inside a security tool. See `specs/04-non-functional-requirements/supply-chain.md`.

- Runtime third-party crates: **`libc` only**. `knsh-exec` has none at all.
- No async runtime (threads + kqueue), no `serde`, no `anyhow`/`thiserror`, no logging, CLI-parsing or TOML crates.
  These are written in-house and kept small.
- A new runtime crate needs a written justification in the PR, review, an exact version pin and vendoring. Build
  scripts must never download anything.
- Test-only crates (fuzzing, property testing) are allowed under `[dev-dependencies]` or in `fuzz/`.

## Architecture rules

- **Mechanism, not policy.** The engine evaluates rules it is given and never authors them.
- **The operating system enforces; the shell observes.** Command rules are intent filters. Hard limits come from the
  sandbox, executable rules, the proxy and credential scoping. Never treat a parser result as a security boundary.
- **One process starts agent commands:** the supervisor in `knshd`, always through `knsh-exec`. Never apply a sandbox
  between `fork` and `exec` inside multithreaded `knshd`.
- **Fail closed for agents, open for humans.** On the decision path every error, timeout or unknown means deny. A
  human session is never blocked.
- **Honest capabilities.** A missing backend is reported as `none` (`hello`), never silently replaced.
- **Functional core, imperative shell.** Parsing, classification, policy evaluation and profile compilation are pure
  functions in library crates. I/O lives at the edges, behind traits.
- **Inject effects** (clock, filesystem, processes, Keychain, authentication prompt, file events, sockets) through
  `knsh-platform` traits so tests are deterministic. Provide fakes in a `testing` module behind a feature flag.
- **Untrusted input** (agent command lines, JSON frames, TOML, TLS handshakes): check size limits before allocating,
  bound recursion depth, never recover from malformed input (reject it), and fuzz every parser.
- **Secrets and privacy:** redact before anything is stored, emitted or sent to hooks or the authority. Never log
  command output, secret values or environment values. Engine files are owner-only (files 0600, dirs 0700).
- **Persistence:** versioned formats, atomic replace (write a temp file, fsync, rename), single writer. A corrupt or
  newer file triggers recovery and is never overwritten.
- **Concurrency:** use standard threads and channels with clear ownership, and no shared mutable state without a
  documented lock order. Never signal a PID that may have been reused; use process groups and keep handles.

## Code style and inline documentation

- **Format:** always `cargo fmt`. Stable rustfmt options only, in `rustfmt.toml`. Never hand-format around it.
- **Lints:** every crate root sets `#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]` and
  `#![warn(clippy::pedantic)]`. Outside tests, `clippy::unwrap_used`, `expect_used` and `panic` are denied.
- **`unsafe`:** allowed only in `knsh-platform` and `knsh-exec`. Every other crate has `#![forbid(unsafe_code)]`. Each
  `unsafe` block has a `// SAFETY:` comment; each `unsafe fn` has a `# Safety` doc section.
- **Inline docs are required:**
  - Each crate has a `//!` header: its purpose, its boundaries, and the spec pages and requirement IDs it implements.
  - Each module has a `//!` summary.
  - Every public item has `///` docs saying what it does and its invariants. Add `# Errors` when it returns
    `Result`, `# Panics` if it can panic (it should not), and an example where it helps.
  - Comments explain *why* (security reasoning, spec references), never restate *what*.
- **Errors:** one hand-written error enum per crate, implementing `std::error::Error` and `Display`. No stringly-typed
  errors across crate boundaries. API error codes (`-32001`…) live only in `knsh-proto`.
- **Types over conventions:** use newtypes for IDs (`SessionId`, `RecordId`), canonical paths (`CanonicalPath`) and
  redacted text (`Redacted<String>`), so that mixing them up fails to compile.
- **Small and explicit:** prefer small functions, exhaustive `match` (no catch-all `_` on enums we own), `pub(crate)`
  by default, and `pub` only for real cross-crate API.

## Tests

- Unit tests sit next to the code (`#[cfg(test)] mod tests`). Integration tests go in each crate's `tests/`.
- Name tests after behaviour, e.g. `denies_line_when_hook_times_out`. Cite the requirement ID in a comment.
- Assert observable behaviour and failure safety: the previous state is kept on error, and the action is denied
  on failure.
- Every parser has a fuzz target in `fuzz/` and round-trip or differential tests. The bash parser is checked
  against real bash and the agent-command corpus (`specs/07-testing/conformance.md`).
- Each row of the threat model (`specs/04-non-functional-requirements/security.md`) has at least one end-to-end test.
- Tests that spawn processes or sandboxes use temp dirs and an isolated state directory, never the user's real one.

## Change workflow

1. Read the relevant spec pages. For a behaviour change or a new feature, update the spec first (or alongside the
   code), adding new requirement IDs with acceptance checks.
2. Implement with tests (observable behaviour and failure safety) and inline docs.
3. Run format, lint, build, doc and the normal test suite (the full suite only on request). All must be clean.
4. Launch an independent review agent with fresh eyes. It looks at correctness, spec gaps, security (fail-closed,
   injection, races, leaks), data loss, regressions and missing tests. It fixes crucial issues, then reruns step 3.
5. Record what was verified and what is still pending in the commit or PR. Update `specs/` when a limit or decision
   changes.
6. Commit with Conventional Commits, using a crate or area as the scope: `feat(knsh-bash): …`, `fix(proxy): …`.

**Honesty rules:** acceptance checks stay unchecked unless actually observed. Manual or platform checks that cannot
run here (Touch ID, Endpoint Security, macOS 27, notarization, older macOS) are recorded as **pending**, never as
passed. Document blockers instead of faking results.

## Gotchas

- An already-sandboxed process cannot apply a second sandbox. Agent CLIs' own sandboxes must be off inside envelopes.
- `/bin/bash` on macOS is 3.2. Agent lines use it unless the profile names another bash.
- Policy denial exits with 126 and always prints the reason on stderr. Exit codes otherwise follow bash.
- Engine paths, `user.sock` and the control service are fixed denies in every profile. No code path may relax them.
- `force` on undo or redo never exists on `agent.sock`.
- Checkpoints must live on the same APFS volume as the files they protect.
