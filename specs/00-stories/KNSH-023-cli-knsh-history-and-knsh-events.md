# KNSH-023 — CLI: `knsh history` and `knsh events`

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | CLI | M (3) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md), [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-018](KNSH-018-event-bus-and-subscriptions.md) | `knsh` | [CLI](../06-api/cli.md) |

**Description.** As a user, I want to search my history and follow events from the command line, in human and
`--json` form.

**Acceptance criteria**
- [x] `knsh history` lists records (newest first) with filters for session, time and text; `--json` prints one JSON
      object per record using the API field names.
- [x] `knsh events [--session <id>] [--since <seq>]` follows events until interrupted; `--json` prints one event per
      line.
- [x] If `knshd` is not reachable, the command exits non-zero with a clear message (it does not start the daemon
      for read-only commands beyond what launchd does on connect).
- [x] Output never contains terminal control sequences from recorded commands unescaped (commands are printed
      safely).

**Unit tests**
- `history_json_uses_api_field_names` — machine-readable output.
- `history_escapes_control_characters` — terminal safety.
- `events_json_one_event_per_line` — streaming format.

**Notes.** Checked against the real `knsh` binary and a stand-in `knshd` on `user.sock`
(`crates/knsh/tests/history_events_integration.rs`), plus unit tests. **Pending:** a manual run against a real
launchd-started `knshd` (it serves only launchd sockets, so tests cannot start it in an isolated home). The API pages
oldest first, so `knsh history` reads every matching page to show the newest; a descending query would make this
cheaper later. Behaviour is specified in [CLI](../06-api/cli.md#history).
