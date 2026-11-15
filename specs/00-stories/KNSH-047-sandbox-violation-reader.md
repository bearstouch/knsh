# KNSH-047 — Sandbox violation reader

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Sandbox | L (5) | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | `knsh-platform`, `knshd` | FR-SBX-06, FR-SBX-08 |

**Description.** As a subscriber, I want sandbox denials reported by the system attributed to a session and command,
best effort, so that agents and humans understand why something failed. Scope: a platform service streaming unified
log entries with the knsh tag (approach from KNSH-025); parsing tags to session, command and rule; emitting
`sandbox.violation` and attaching to the record's `sandbox_violations`.

**Acceptance criteria**
- [ ] The reader runs as the user without admin rights. *(Runs as the user, never through `sudo`, observed on an
  account in `admin`; a standard account is pending.)*
- [x] Entries without a parseable knsh tag are ignored, never mis-attributed.
- [x] Duplicates within a short window are merged; delayed entries arriving after a record is finished are appended
  to that record.
- [x] Reader failure is reported through the capability report and never blocks or fails a command.
- [x] The log message parser is a pure function with tests over captured real samples (from KNSH-025).

**Unit tests**
- `parses_tagged_denial_message`.
- `ignores_untagged_message`.
- `merges_duplicate_denials`.
- `attaches_late_denial_to_finished_record`.

**Notes.** — Format can change between macOS versions; samples per version are kept as fixtures.

Done on macOS 26.6.2 (Apple M1 Pro). The wire forms are in [execution record](../05-models/execution-record.md#sandbox_violations),
[event](../05-models/event.md#phase-2-payloads) and [capabilities](../05-models/capabilities.md#probe).

- *Where it lives:* the tag, violation, merger and bounded append (`merge_into`) are pure in `knsh-core`
  (`violation`); the log parser is pure in `knsh-platform` (`violation::parse_entry`), with the `DenialLog` trait,
  the macOS `UnifiedLogDenials` backend (`log stream --style ndjson` and a `sandbox-exec -p` canary, safe `std`
  only) and the `ScriptedDenialLog` fake; the reader threads and the record and event sink are in `knshd`
  (`violations`); the record store gained `append_sandbox_violations`. `knsh-platform` now depends on `knsh-json`.
- *Attribution:* only by an exact tag (`DenialTag`) on the last of exactly two message lines, from an entry the
  kernel logged (`processID` 0, `processImagePath` `/kernel`), so a user process logging under the sender name
  `Sandbox`, a spike tag (`knsh:c8:…`), an untagged refusal or a path holding a newline is ignored
  (`ignores_untagged_message`, `ignores_ambiguous_or_malformed_reports`, `ignores_entries_not_from_the_kernel`). A
  violation is attached only to the agent record of the session its tag names; an envelope's (`env`) is published
  but attached to no record. A process outside knsh that reads a path ending in a newline and a forged knsh tag
  could still produce an entry that looks tagged; it would need the target's session and record IDs, and
  violations are never an input to a decision.
- *Merging:* identical denials (tag, process, pid, operation, argument) within 3 s are one violation with the summed
  count, the system's "N duplicate reports" included; at most 1024 pending, the oldest released early beyond that.
  Late ones merge into the stored record (`appends_late_violations_to_a_finished_record`), at most 256 distinct per
  record. While a line runs, its violations are held and written once its record is (`line_started`,
  `line_recorded`, for the supervisor in KNSH-050; tested, not yet called).
- *Liveness and failure:* `capabilities.sandbox_violations` is `unified_log` only while a canary has come back
  through the current stream (decision 9), read live at each `hello`. A stream that cannot open or ends is reported
  in the system log and reopened with backoff; the reader runs on its own threads with a bounded queue, so it never
  blocks a command. `knshd` stops it on an orderly exit, so `log stream` does not outlive it; if `knshd` is killed (`SIGKILL`), the
  orphaned `log stream` lives until its next write fails with `SIGPIPE` (the next knsh denial or canary).
- *Large integers:* log entries carry 64-bit fields the strict JSON reader refuses (`machTimestamp` passes 2^53
  after about 104 days of uptime on Intel). The parser rewrites integer literals of more than 15 digits outside
  strings as decimal text before reading, so such entries are still read (found in review).
- *Fuzzing:* new `sandbox_log` target (seeds: the fixture lines); 60 s smoke run here, about 2 million inputs, no
  failure. Replayed on stable by `crates/knsh-platform/tests/fuzz_regressions.rs`.

**Pending:** the first criterion on a standard (non-admin) account; macOS 14 and 15 samples and behaviour; wiring
`line_started` and `line_recorded` into the supervisor (KNSH-050).
