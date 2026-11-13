# KNSH-021 — Human telemetry, recording indicator and idle event

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Human shell | L (5) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-019](KNSH-019-integration-mode-hosting-stock-zsh.md) | `knsh`, `knshd` | FR-SES-21, FR-SES-23, FR-REC-09, NFR-REL-02, NFR-PRIV-01, FR-SES-24, FR-SES-25, NFR-PRIV-05 |

**Description.** Merged from *Human telemetry recording* and *Recording indicator, `session.info` and `session.idle`*: they are done and validated together because the same recorded human session exercises all three.

*Human telemetry recording.* As a user who opted in, I want each command line I type recorded with its directory, times and exit
code, so that I have a searchable history. `knsh` starts a human session over `user.sock` only when recording is on,
then forwards telemetry lines. If `knshd` is unreachable, telemetry is dropped and the shell is unaffected.

*Recording indicator, `session.info` and `session.idle`.* As a user, I want to see when I am being recorded, and clients want to know when a prompt is idle.

**Acceptance criteria**
*Human telemetry recording*

- [ ] Recording is off by default; when off, `knsh` never connects to `knshd` (FR-SES-23).
- [ ] When on, a human session is created with `actor.kind = human`; each typed line produces one record with
      `command`, `cwd`, `started_at`, `ended_at`, `exit_code` only, and a `command.finished` event.
- [ ] `cwd.changed` is emitted when the working directory changes.
- [ ] If `knshd` is unreachable or goes away, telemetry is dropped silently; the prompt is never delayed by more
      than a fixed small bound and never blocked (NFR-REL-02).
- [ ] The session is ended (`session.ended`) when the shell exits.
- [ ] Nothing leaves the machine (NFR-PRIV-01).

*Recording indicator, `session.info` and `session.idle`*

- [ ] A recording session exports `KNSH_RECORDING=1` to the shell; a non-recording session does not set it.
- [ ] `session.info` returns actor, profile, state and recording settings for the caller's session.
- [ ] `session.idle` is emitted once when a human prompt has waited 5 seconds for input, and again only after a new
      command.

**Unit tests**
*Human telemetry recording*

- `recording_off_never_connects` — FR-SES-23 (fake connector counts attempts).
- `unreachable_daemon_drops_telemetry_without_blocking` — NFR-REL-02.
- `record_contains_only_telemetry_fields` — FR-REC-09.

*Recording indicator, `session.info` and `session.idle`*

- `recording_sets_knsh_recording_env` — FR-SES-25.
- `idle_emitted_once_after_5_seconds` — FR-SES-24 (fake clock).
- `session_info_reports_recording_state` — NFR-PRIV-05.

**Integration tests**
*Human telemetry recording*

- With recording on, type three commands in a scripted terminal; `knsh history --json` shows exactly three records.
- Stop `knshd` mid-session; the shell keeps working.

**Notes**
*Human telemetry recording*

— Where the human opts in (a config key in `~/.config/knsh/`, a flag, or both) is not specified; propose a
`[recording] human = true` user setting in the spec before implementing.
