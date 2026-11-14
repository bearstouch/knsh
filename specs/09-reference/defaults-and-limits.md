# Defaults and limits

| Setting | Default or limit | Configurable | Source |
| --- | --- | --- | --- |
| `knshd` idle exit | 10 minutes | — | [process model](../02-architecture/process-model.md) |
| `knshd` concurrent connections | 64 over both sockets; further connections are closed on accept | — | [process model](../02-architecture/process-model.md) |
| First message (`hello`) timeout | 10 s after connecting, then the connection is closed | — | [process model](../02-architecture/process-model.md) |
| Write to a client | 30 s blocked, then the connection is closed | — | [process model](../02-architecture/process-model.md) |
| Shutdown grace | 5 s for in-flight requests, then connections are closed | — | [process model](../02-architecture/process-model.md) |
| Authority decision timeout | 90 s, then deny | Yes; set shorter than the agent CLI's tool timeout | [authority](../03-functional-requirements/authority.md) |
| Hook timeout | `timeout_ms` per hook (example 2000) | Per hook | [hooks](../03-functional-requirements/hooks.md) |
| Rate limit | 5 denials of the same normalised line in 60 s → denied for 10 minutes | — | [hooks](../03-functional-requirements/hooks.md) |
| `command.long_running` | 30 s | Yes | [command lifecycle](../03-functional-requirements/command-lifecycle.md) |
| `session.idle` | 5 s at a human prompt | — | [sessions](../03-functional-requirements/sessions.md) |
| Human recording | Off | `[recording] human` in `~/.config/knsh/config.toml` | [terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session) |
| Human telemetry queue in `knsh` | 1024 lines, then dropped | — | [terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session) |
| Human telemetry reconnect | At most once every 30 s, at the next line | — | [terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session) |
| Human telemetry timeouts | 5 s to start the session, 1 s per call, 500 ms at shell exit | — | [terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session) |
| `telemetry.command` | `command` 64 KiB, `cwd` 16 KiB | No | [user socket](../06-api/user-socket.md#human-sessions) |
| Event buffer | Last 10,000 events per session | — | [events](../03-functional-requirements/events.md) |
| Ended sessions' event buffers | The 64 most recently ended sessions | — | [user socket](../06-api/user-socket.md#events) |
| Events queued per subscription | 10,000, then the oldest are dropped and reported (`events.lost`) | — | [user socket](../06-api/user-socket.md#events) |
| Subscriptions per connection | 16 | — | [user socket](../06-api/user-socket.md#events) |
| Record retention | 30 days or 2 GB, first reached; days per record by its session's profile, 2 GB for the whole store | Days per profile (`recording.retention_days`, 1 to 36500) | [execution records](../03-functional-requirements/execution-records.md#retention) |
| Retention runs | At store open, then hourly; batches of 500 records | — | [execution records](../03-functional-requirements/execution-records.md#retention) |
| Recorded output per stream | 1 MB, then head and tail | Yes | [execution records](../03-functional-requirements/execution-records.md) |
| `records.query` page size | 100 by default, at most 1000 | No | [user socket](../06-api/user-socket.md#records) |
| `records.query` text filter | 4096 bytes | No | [user socket](../06-api/user-socket.md#records) |
| `records.output` inline base64 | 512 KiB per call | No | [user socket](../06-api/user-socket.md#records) |
| `full` output mode | 1 MB per stream | — | [output modes](../03-functional-requirements/output-modes.md) |
| `errors_only` stdout lines | Last 20 | — | [output modes](../03-functional-requirements/output-modes.md) |
| Frame payload | 1 MB | — | [wire format](../06-api/wire-format.md) |
| JSON nesting | 32 levels | — | [wire format](../06-api/wire-format.md) |
| JSON integers | ±2^53 | — | [wire format](../06-api/wire-format.md) |
| Content hash in post-image identity | Files under 64 MB | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Checkpoint retention | 5 GB per volume, 200 per root, or 7 days | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Sensitive-file pre-images | 24 hours at most | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Plain-copy checkpoints (non-APFS) | 50 MB per change | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Checkpoint excludes | `node_modules`, `target`, `.venv`, `dist`, `build` | `checkpoints.exclude` | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Rewrites per line | 1 | — | [authority](../03-functional-requirements/authority.md) |
| Deprecated method lifetime | 2 engine minor releases | — | [API](../06-api/README.md) |
| Human recording | Off | Per session | [privacy](../04-non-functional-requirements/privacy.md) |
| Agent recording | Commands on, output off | Per profile, `recording.set` | [privacy](../04-non-functional-requirements/privacy.md) |
| `fs.read` | `"all"` (except deny list) | Per profile | [policy](../03-functional-requirements/policy.md) |
| Agent bash | `/bin/bash` (3.2) | Per profile | [compatibility](../04-non-functional-requirements/compatibility.md) |
| Trusted folders | `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` | Profile can add | [policy](../03-functional-requirements/policy.md) |
