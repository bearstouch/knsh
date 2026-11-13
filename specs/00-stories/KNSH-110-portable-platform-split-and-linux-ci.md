# KNSH-110 — Portable platform split and Linux CI

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Platform | M (3) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | `knsh-platform`, all | platform-support.md (all rows), NFR-SUP-07 |

**Description.** As a developer, I want `knsh-platform` split into a shared interface plus `macos` and `linux`
backends selected at compile time, and CI building and testing on Linux, so that every later Linux story has a place
to land and regressions are caught.

Scope: `cfg(target_os)` module layout, a capability probe that reports `none` for every backend not yet implemented
on Linux, Linux CI job (build, test, clippy, doc) with the same flags as macOS, and container-based test runs.

**Acceptance criteria**
- [ ] The workspace builds on Linux with `--offline --locked`, warning-free.
- [ ] Platform-independent crates (`knsh-core`, `knsh-bash`, `knsh-json`, `knsh-toml`, `knsh-proto`) pass all tests
      on Linux unchanged.
- [ ] `hello` on Linux reports `none` for unimplemented backends; agent sessions refuse to start without a sandbox
      (NFR-REL-08, FR-AGT-06).
- [ ] No macOS-only symbol is referenced outside the `macos` backend.

**Unit tests**
- `probe_reports_none_for_unimplemented_backends`
- `agent_session_refused_without_sandbox_backend`

**Integration tests**
- CI job on a current LTS distribution runs the full test suite.
