# KNSH-005 — Fuzzing harness

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Foundations | S (2) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md), [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md), [KNSH-006](KNSH-006-toml-subset-parser.md) | `fuzz/` (test-only) | NFR-SUP-05, NFR-SUP-06, [fuzzing](../07-testing/fuzzing.md) |

**Description.** As a maintainer, I want fuzz targets for every hand-written parser of untrusted input, so that
panics and limit violations are found continuously. Starts with the JSON reader, JSON round trip and frame reader;
the TOML target is added by KNSH-006 when both exist, the bash target in phase 2. Out of scope: running fuzzers
indefinitely in CI (a time-boxed smoke run only).

**Acceptance criteria**
- [ ] `fuzz/` is outside the shipped workspace members and uses only test-only crates (NFR-SUP-05).
- [ ] Targets: `json_reader` (no panic; accept ⇒ round trip equal), `json_writer_roundtrip`, `frame_reader`
      (no panic; never allocates beyond the limit).
- [ ] Seed corpora are checked in, including the KNSH-003 accept/reject samples.
- [ ] CI runs each target for a fixed short time on every push; crashes fail the pipeline and the crashing input
      is stored as an artefact.
- [ ] A documented command runs long fuzzing locally (`cargo +nightly fuzz run <target>`).

**Unit tests**
- `fuzz_regressions_replay` — every saved crash input in `fuzz/regressions/` is replayed as an ordinary test.
