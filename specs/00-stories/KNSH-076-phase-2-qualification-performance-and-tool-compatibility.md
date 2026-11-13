# KNSH-076 — Phase 2 qualification: performance and tool compatibility

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Qualification | L (5) | [KNSH-053](KNSH-053-output-capture-command-output-and-exec-with-output-modes.md), [KNSH-058](KNSH-058-agent-cli-presets-claude-code-codex-cli-generic.md) | `benches/` (workspace), docs | NFR-PERF-01, NFR-PERF-02, NFR-PERF-03, NFR-PERF-07, NFR-PERF-08, [performance validation](../07-testing/performance-validation.md), FR-SBX-09, FR-NET-12, [developer tools](../08-integrations/developer-tools.md) |

**Description.** Merged from *Phase 2 performance qualification* and *Tool compatibility list*: they are done and validated together because both run on the same qualification machine and release checklist.

*Phase 2 performance qualification.* As the release owner, I want the phase 2 performance targets measured on Apple silicon, so that
supervision is shown to be cheap enough for agents.

*Tool compatibility list.* As a user, I want a published list of which developer tools work inside envelopes and command
profiles, so that I know what to expect and when to use trusted tools.

**Acceptance criteria**
*Phase 2 performance qualification*

- [ ] Supervisor decision without hooks or authority: p95 under 5 ms over the corpus.
- [ ] Spawn overhead versus plain `bash -c`: p95 under 15 ms for trivial commands.
- [ ] Hook time is reported per record, bounded by its timeout.
- [ ] Event delivery: p95 under 10 ms.
- [ ] `knshd` idle memory under 50 MB.
- [ ] A report with the machine, macOS version and raw numbers is stored with the release. Misses are recorded,
      not rounded away.

*Tool compatibility list*

- [ ] The list covers at least curl, git (HTTPS and ssh remotes), npm, pip, cargo, Node HTTP clients, Chromium and
      Playwright, `swift build` and Bazel, each with a status (works, blocked or needs a trusted tool).
- [ ] Each entry records the macOS version and tool version tested.
- [ ] The list is published in [developer tools](../08-integrations/developer-tools.md) for the release.

**Unit tests**
*Phase 2 performance qualification*

- `benchmark_harness_reports_p95` — the harness computes percentiles correctly on fixed samples.

*Tool compatibility list*

- None. This is a documentation and verification story; results come from the KNSH-027 and KNSH-058 runs.
