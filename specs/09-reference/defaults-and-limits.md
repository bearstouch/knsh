# Defaults and limits

| Setting | Default or limit | Configurable | Source |
| --- | --- | --- | --- |
| `knshd` idle exit | 10 minutes | — | [process model](../architecture/process-model.md) |
| Authority decision timeout | 90 s, then deny | Yes; set shorter than the agent CLI's tool timeout | [authority](../functional-requirements/authority.md) |
| Hook timeout | `timeout_ms` per hook (example 2000) | Per hook | [hooks](../functional-requirements/hooks.md) |
| Rate limit | 5 denials of the same normalised line in 60 s → denied for 10 minutes | — | [hooks](../functional-requirements/hooks.md) |
| `command.long_running` | 30 s | Yes | [command lifecycle](../functional-requirements/command-lifecycle.md) |
| `session.idle` | 5 s at a human prompt | — | [sessions](../functional-requirements/sessions.md) |
| Event buffer | Last 10,000 events per session | — | [events](../functional-requirements/events.md) |
| Record retention | 30 days or 2 GB, first reached | Per profile | [execution records](../functional-requirements/execution-records.md) |
| Recorded output per stream | 1 MB, then head and tail | Yes | [execution records](../functional-requirements/execution-records.md) |
| `full` output mode | 1 MB per stream | — | [output modes](../functional-requirements/output-modes.md) |
| `errors_only` stdout lines | Last 20 | — | [output modes](../functional-requirements/output-modes.md) |
| Frame payload | 1 MB | — | [wire format](../api/wire-format.md) |
| JSON nesting | 32 levels | — | [wire format](../api/wire-format.md) |
| JSON integers | ±2^53 | — | [wire format](../api/wire-format.md) |
| Content hash in post-image identity | Files under 64 MB | — | [checkpoints](../functional-requirements/checkpoints.md) |
| Checkpoint retention | 5 GB per volume, 200 per root, or 7 days | — | [checkpoints](../functional-requirements/checkpoints.md) |
| Sensitive-file pre-images | 24 hours at most | — | [checkpoints](../functional-requirements/checkpoints.md) |
| Plain-copy checkpoints (non-APFS) | 50 MB per change | — | [checkpoints](../functional-requirements/checkpoints.md) |
| Checkpoint excludes | `node_modules`, `target`, `.venv`, `dist`, `build` | `checkpoints.exclude` | [checkpoints](../functional-requirements/checkpoints.md) |
| Rewrites per line | 1 | — | [authority](../functional-requirements/authority.md) |
| Deprecated method lifetime | 2 engine minor releases | — | [API](../api/README.md) |
| Human recording | Off | Per session | [privacy](../nonfunctional-requirements/privacy.md) |
| Agent recording | Commands on, output off | Per profile, `recording.set` | [privacy](../nonfunctional-requirements/privacy.md) |
| `fs.read` | `"all"` (except deny list) | Per profile | [policy](../functional-requirements/policy.md) |
| Agent bash | `/bin/bash` (3.2) | Per profile | [compatibility](../nonfunctional-requirements/compatibility.md) |
| Trusted folders | `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` | Profile can add | [policy](../functional-requirements/policy.md) |
