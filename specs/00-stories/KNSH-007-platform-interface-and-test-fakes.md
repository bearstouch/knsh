# KNSH-007 — Platform interface and test fakes

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Platform | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md), [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | `knsh-platform` | [implementation](../02-architecture/implementation.md#platform-interface), [macOS services](../08-integrations/macos-services.md) |

**Description.** As an engine developer, I want every effect behind a trait with a deterministic fake, so that core
logic is tested without clocks, real files, processes or system services. This story defines the first traits and
their macOS implementations: `Clock` (wall and monotonic), `Random`, `Fs` (open, read, write, atomic replace with
fsync and rename, mkdir with mode, metadata, canonicalise), `Processes` (spawn, process groups, signals by group,
wait), `SystemLog` (unified logging subsystem `knsh`). Fakes live in a `testing` module behind a `testing` cargo
feature. Later stories add Keychain, LocalAuthentication, XPC, FSEvents and clones to the same interface.
Out of scope: those later services.

**Acceptance criteria**
- [ ] Traits are object-safe or generic as appropriate, `Send + Sync`, and documented with their error cases.
- [ ] `unsafe` is confined to the macOS backend modules; every block has a `// SAFETY:` comment.
- [ ] `Fs::atomic_replace` writes a temp file in the same directory, fsyncs it, renames over the target and fsyncs
      the directory; on any error the previous file is untouched.
- [ ] `Fs::canonicalise` returns `CanonicalPath` (KNSH-002) with symlinks followed (`/var` → `/private/var`).
- [ ] `Processes` signals only process groups it created and holds handles; it never signals a bare PID that may
      have been reused.
- [ ] `SystemLog` never accepts command output or secret values (API takes static message plus typed fields).
- [ ] Fakes: controllable clock, seeded random, in-memory filesystem with fault injection, scripted processes.

**Unit tests**
- `atomic_replace_keeps_previous_file_on_write_error` — failure safety (fake fs with injected error).
- `canonicalise_follows_symlinks` — FR-POL-11 (real fs, temp dir).
- `fake_clock_advances_only_when_told` — determinism.
- `signal_refuses_unknown_process_group` — no reused-PID signalling.

**Integration tests**
- macOS backend: spawn `/bin/sh -c 'sleep 10'` in a new process group, signal the group, observe exit by signal.
