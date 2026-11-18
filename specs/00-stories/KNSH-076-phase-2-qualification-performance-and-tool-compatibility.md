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

- [x] Supervisor decision without hooks or authority: p95 under 5 ms over the corpus. *(0.29 ms over 2,350 lines,
      allowed and refused.)*
- [ ] Spawn overhead versus plain `bash -c`: p95 under 15 ms for trivial commands. **Missed:** 55.14 ms added at p95
      (`true`; `echo hi` 53.77 ms), about 38 ms at p50. Measured and recorded; the cost is in the supervisor's spawn path
      (follow-up below).
- [x] Hook time is reported per record, bounded by its timeout. *(Every record lists its hook's `duration_ms`, never
      above the timeout; a hook hanging past 500 ms has its line decided within 507.19 ms.)*
- [x] Event delivery: p95 under 10 ms. *(0.05 ms over 2,355 events on a real `user.sock` subscriber; none lost.)*
- [x] `knshd` idle memory under 50 MB. *(8.98 MB RSS after 60 s idle, real `knshd` under launchd.)*
- [x] A report with the machine, macOS version and raw numbers is stored with the release. Misses are recorded,
      not rounded away. *([qualification/](../07-testing/qualification/README.md): report and every raw sample.)*

*Tool compatibility list*

- [ ] The list covers at least curl, git (HTTPS and ssh remotes), npm, pip, cargo, Node HTTP clients, Chromium and
      Playwright, `swift build` and Bazel, each with a status (works, blocked or needs a trusted tool). *(Observed for
      all but Playwright's Node driver and Bazel, which are not installed on the qualification machine: listed as
      pending with their expected status.)*
- [ ] Each entry records the macOS version and tool version tested. *(Every tested entry does; Playwright's driver and
      Bazel are pending.)*
- [x] The list is published in [developer tools](../08-integrations/developer-tools.md) for the release.

**Unit tests**
*Phase 2 performance qualification*

- `benchmark_harness_reports_p95` — the harness computes percentiles correctly on fixed samples.

*Tool compatibility list*

- None. This is a documentation and verification story; results come from the KNSH-027 and KNSH-058 runs.

**Notes (KNSH-076)**
- Where it lives: `crates/knshd/src/qualification/` (not a workspace `benches/` crate). `knshd` has no library target,
  and a real `knshd` runs agent lines only for profiles signed after Touch ID, so the runs drive the threat-model
  suite's miniature `knshd` (`threat_model::harness::Stack`, now with `Wiring` for a stub spawner, real hooks and a
  system-clock event hub). Idle memory uses the real `knshd` under a test launchd job. Run with
  `scripts/qualify-phase2.sh`; method in [performance validation](../07-testing/performance-validation.md).
- Found by the idle-memory run: `knshd` crashed at start-up under launchd (`CFRelease(NULL)`) whenever no authority
  was trusted, because `bool::then_some` built the owning wrapper of a null Keychain result eagerly. Fixed in
  `knsh-platform` (`keychain.rs`, `xpc.rs`, `presence.rs`), with regression tests; `tests/launchd_agent.rs`, which
  failed on this machine before, passes again.
- **Follow-up (NFR-PERF-02 missed):** break down the supervisor's spawn path (34 ms at p50 in-process, of which
  `sandbox-exec` is about 10 ms) and bring the added p95 under 15 ms, or revisit the target.
- **Pending:** the same runs on macOS 14 and 15; memory after a long busy period; trusted-tool runs of Chromium and
  `swift build` (need an approval or a Touch ID grant); Playwright's Node driver and Bazel (not installed).
