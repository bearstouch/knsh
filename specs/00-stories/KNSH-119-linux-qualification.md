# KNSH-119 — Linux qualification

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Qualification | L (5) | [KNSH-111](KNSH-111-in-house-sha-256-and-hmac-replacing-commoncrypto.md), [KNSH-112](KNSH-112-systemd-units-socket-activation-and-control-channel-with-so.md), [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md), [KNSH-114](KNSH-114-network-confinement-seccomp-or-network-namespace.md), [KNSH-115](KNSH-115-inotify-fanotify-watcher-and-reflink-checkpoints.md), [KNSH-116](KNSH-116-secret-service-backend.md), [KNSH-117](KNSH-117-journald-logging-and-violation-reading.md), [KNSH-118](KNSH-118-spike-user-presence-check-for-approvals-on-linux.md) | CI | NFR-SEC-*, NFR-PERF-*, platform-support.md |

**Description.** As the release owner, I want the threat-model suite, performance benchmarks and compatibility list
run on Linux, so that the Linux release makes the same honest claims as macOS.

**Acceptance criteria**
- [ ] Threat-model end-to-end suite (KNSH-075) passes on Linux, or each failing row is documented as unsupported and
      reported via `hello`.
- [ ] Performance targets are measured on a reference Linux machine; any target not met is documented.
- [ ] The API conformance tests produce identical results on macOS and Linux.
- [ ] Tool compatibility list published for Linux.

**Unit tests**
- `api_conformance_suite_runs_against_both_platforms`

**Integration tests**
- Full suite in CI on at least one distribution with Landlock and one without (expect agent sessions to refuse).
