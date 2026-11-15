# KNSH-053 — Output capture, `command.output` and `exec.*` with output modes

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | XL (8) | [KNSH-018](KNSH-018-event-bus-and-subscriptions.md), [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md) | `knshd`, `knsh-store`, `knsh-proto` | FR-LC-18, FR-REC-06, FR-EVT-07, FR-OUT-01, FR-OUT-02, FR-OUT-05, FR-AUTH-33, [agent socket](../06-api/agent-socket.md), [output modes](../03-functional-requirements/output-modes.md) |

**Description.** Merged from *Output capture and `command.output`* and *`exec.run`, `exec.start`, `exec.wait`, `exec.kill` and output modes*: they are done and validated together because output modes are validated through captured output.

*Output capture and `command.output`.* As an observer, I want a line's output captured, capped and emitted when the session records output,
so that it can be reviewed without flooding storage.

In scope:
- Capture for `exec.run` and `exec.start` callers.
- Storage when `recording.output` is on.
- `command.output` events.

Redaction of secrets arrives in phase 3 (KNSH-091), but the capture path already has a redaction hook point
(a no-op in phase 2).

*`exec.run`, `exec.start`, `exec.wait`, `exec.kill` and output modes.* As an agent that integrates natively, I want structured `exec.*` methods with output modes, so that
I get exit codes, decisions and only as much output as my context can afford.

**Acceptance criteria**
*Output capture and `command.output`*

- [x] With `recording.output = false` (the default), no output is stored and no `command.output` is emitted.
- [x] With output recording on, stdout and stderr are stored up to 1 MB each. Beyond that, head and tail are kept
      and the skipped size is recorded.
- [x] `command.output` chunks are emitted in order, as binary stream frames on the sockets (base64 for a client
      that opted out of binary frames).
- [x] For `knsh -c`, output still goes directly to the caller's descriptors. Capture for storage tees without
      changing what the caller sees.
- [x] Every chunk passes through the redaction hook before it is stored or emitted.

*`exec.run`, `exec.start`, `exec.wait`, `exec.kill` and output modes*

- [x] `exec.run` accepts `command`, `cwd`, `timeout_s` and `output {mode, max_bytes, lines}`, and returns
      `record_id`, `executed_command`, `exit_code`, `duration_ms`, mode-dependent output, `decision`,
      `files_changed` and `checkpoint_id`. Both are `null` until checkpoints exist (phase 3): a count of 0 would
      claim something was measured.
- [x] Mode `full` returns everything up to 1 MB per stream. `truncate` returns the first `max_bytes`. `head_tail`
      returns the first and last `lines` lines with a skipped count. `errors_only` returns stderr, the exit code and
      the last 20 stdout lines. `ref` returns sizes, line counts and the `record_id`.
- [x] With no mode given, the profile's default mode applies.
- [x] `exec.start` returns once the line is spawned (or denied). `exec.wait` returns the same result as `exec.run`.
      `exec.kill` kills the line's process group.
- [x] Errors: `-32001` denied, `-32002` decision timeout, `-32007` held, `-32008` killed at timeout, `-32011`
      cancelled.
- [x] `executed_command` equals the line actually spawned, after any rewrite.
- [x] The engine never summarises output.

**Unit tests**
*Output capture and `command.output`*

- `stores_nothing_when_output_recording_off` — FR-REC-06.
- `keeps_head_and_tail_beyond_one_megabyte` — FR-REC-06.
- `emits_output_events_only_when_recording` — FR-LC-18.
- `every_chunk_passes_redaction_hook` — FR-EVT-07.

*`exec.run`, `exec.start`, `exec.wait`, `exec.kill` and output modes*

- `full_mode_caps_each_stream_at_one_megabyte` — FR-OUT-01.
- `truncate_returns_first_max_bytes` — FR-OUT-01.
- `head_tail_reports_skipped_line_count` — FR-OUT-01.
- `errors_only_returns_last_twenty_stdout_lines` — FR-OUT-01.
- `ref_mode_returns_sizes_and_record_id_only` — FR-OUT-01.
- `uses_profile_default_mode_when_absent` — FR-OUT-02.
- `returns_executed_command_after_rewrite` — FR-AUTH-33.
- `kill_terminates_whole_process_group` — exec API.

**Notes**
*Output capture and `command.output`*

- Teeing `knsh -c` output means `knshd` must sit in the data path when output recording is on (a pipe pair instead of
  a direct descriptor). Confirm the latency effect in KNSH-076. **Pending** (not measured here). The line's stdout and
  stderr are then pipes, so `isatty` is false for them.
- `session.info` still reports `output_recording: false` for agent sessions: it would need the session's profile,
  which the registry does not load yet. **Pending** follow-up.

*`exec.run`, `exec.start`, `exec.wait`, `exec.kill` and output modes*

- Spec gap resolved in [agent socket](../06-api/agent-socket.md#execstart-execwait-execkill): the handle is the
  `record_id` `exec.start` returns; `exec.wait` takes no timeout (the line's `timeout_s` bounds it, `exec.kill` ends it
  sooner); the first `exec.wait` collects the result; at most 64 uncollected lines per session.
- Spec gap resolved: a `full` answer of two 1 MB streams cannot fit in one 1 MB frame, so output text is cut to fit
  (`cut_to_fit`), and output that is not UTF-8 is shown with U+FFFD ([result](../06-api/agent-socket.md#result)).
