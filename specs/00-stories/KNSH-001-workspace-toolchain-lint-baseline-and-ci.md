# KNSH-001 — Workspace, toolchain, lint baseline and CI

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Foundations | L (5) | — | all (skeletons), — (CI config) | NFR-SUP-01 – NFR-SUP-05, [implementation](../02-architecture/implementation.md), NFR-SUP-03, NFR-SUP-04, NFR-COMPAT-07, [test strategy](../07-testing/test-strategy.md) |

**Description.** Merged from *Cargo workspace, toolchain and lint baseline* and *CI pipeline*: they are done and validated together because the first CI run is the acceptance test of the workspace baseline.

*Cargo workspace, toolchain and lint baseline.* As a contributor, I want a workspace whose structure and quality gates are fixed from the first
commit, so that every crate starts with the same lints, docs rules and offline build. Create the Cargo workspace with
every crate from the `CLAUDE.md` layout as an empty skeleton (`knsh-core`, `knsh-bash`, `knsh-json`, `knsh-toml`,
`knsh-proto`, `knsh-platform`, `knsh-sandbox`, `knsh-proxy`, `knsh-store`, `knsh-checkpoint`, `knshd`, `knsh`,
`knsh-exec`), `rust-toolchain.toml` (stable, edition 2024), `rustfmt.toml` (stable options only), a
`.cargo/config.toml` that points sources at `vendor/`, and the lint headers. Out of scope: any functionality.

*CI pipeline.* As a maintainer, I want every push checked for format, lints, docs, offline build, tests and
dependency hygiene, so that the rules in `CLAUDE.md` are enforced, not remembered. Out of scope: fuzzing runs
(KNSH-005), conformance suites (phase 2).

**Acceptance criteria**
*Cargo workspace, toolchain and lint baseline*

- [ ] `cargo build --workspace --offline --locked` succeeds with zero warnings on a clean checkout with no network.
- [ ] Every crate root has a `//!` header (purpose, boundaries, spec pages) and
      `#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]` plus `#![warn(clippy::pedantic)]`.
- [ ] Every crate except `knsh-platform` and `knsh-exec` has `#![forbid(unsafe_code)]`.
- [ ] `clippy::unwrap_used`, `clippy::expect_used` and `clippy::panic` are denied outside `#[cfg(test)]` (workspace
      lints table).
- [ ] The dependency graph matches the layout table: no crate depends upwards; `knsh-exec` has no dependencies at
      all; the only third-party runtime crate in `Cargo.lock` is `libc`, used only by `knsh-platform`.
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
      `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` are clean.
- [ ] `libc` is pinned to an exact version and vendored; a short justification is recorded in `vendor/README.md`.

*CI pipeline*

- [ ] CI runs on macOS (Apple silicon) for every push and pull request: `cargo fmt --all --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build --workspace --offline --locked`,
      `cargo doc` with `RUSTDOCFLAGS="-D warnings"`, `cargo test --workspace --offline`.
- [ ] The build step runs with network access disabled (or `CARGO_NET_OFFLINE=true`) and fails if any build script
      tries to download (NFR-SUP-03).
- [ ] Licence, advisory and duplicate-version checks run (`cargo deny`), installed in CI only and never added to the
      workspace (NFR-SUP-04).
- [ ] Any failing step fails the pipeline; there are no "allowed to fail" steps.
- [x] A local script `scripts/check.sh` runs the same steps in the same order.

**Unit tests**
*Cargo workspace, toolchain and lint baseline*

- `workspace_has_no_third_party_runtime_deps_except_libc` — a test (in a dev-only `xtask` or test crate) parses
  `Cargo.lock` and fails on any other runtime package (NFR-SUP-01, NFR-SUP-02).
- `knsh_exec_has_no_dependencies` — parses `knsh-exec/Cargo.toml` and asserts an empty `[dependencies]` (NFR-SUP-01).

*CI pipeline*

- None (configuration). The pipeline is verified by a deliberately failing branch for each gate (format, lint,
  doc warning, test failure, forbidden dependency) — recorded in the PR.

**Notes**
*Cargo workspace, toolchain and lint baseline*

— `cargo metadata` would be the natural tool for the dependency checks; parsing `Cargo.lock` keeps the
test free of extra crates.

*CI pipeline*

— Pin the CI runner's Xcode/macOS version; record it in the pipeline file.
