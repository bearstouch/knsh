# Execution record

One record per agent command line that reaches lifecycle step 2. Stored in the record store (SQLite, internal format); exposed only through `records.query` and `records.output`. Behaviour is in [../functional-requirements/execution-records.md](../functional-requirements/execution-records.md).

| Field | Type | Notes |
| --- | --- | --- |
| `record_id` | ULID | Primary key |
| `session_id` | ULID | Owning session |
| `actor` | object | `kind` and `agent_id` |
| `attribution` | `command` \| `agent_edit` \| `external` \| `concurrent` | How the record's file changes were attributed ([checkpoints](../functional-requirements/checkpoints.md)) |
| `command` | string | The line actually executed, after any rewrite, with secrets redacted |
| `rewritten_from` | string or null | The original line when a rewrite was applied |
| `argv` | array | Each simple command with resolved absolute path and class (`static`, `wrapper`, `dynamic`, `project_executable`) |
| `cwd` | path | Working directory at start |
| `decision` | object | See below |
| `sandbox_profile` | string | Profile name and a hash of the compiled profile |
| `secrets_injected` | array | Secret names only, never values |
| `started_at`, `ended_at` | timestamp | UTC, microseconds |
| `exit_code` | int or null | Exit code of the line; null when denied or still running |
| `pipestatus` | array | Exit code of each command in the last pipeline |
| `signal` | string or null | e.g. `SIGKILL` |
| `stdout`, `stderr` | blob reference | Only when output recording is on; capped at 1 MB each by default, then head and tail kept |
| `children` | array | Processes seen in the command's process groups, best effort |
| `files_changed` | array | Paths created, modified or deleted under checkpoint roots, with post-image identity |
| `network` | array | Hosts contacted or refused, as reported by the proxy |
| `checkpoint_id` | ID or null | Checkpoint holding the pre-images |
| `irreversible` | bool + reasons | From classification and observed behaviour |
| `sandbox_violations` | array | Denials the system reported for this command, best effort |

## `decision`

| Field | Values |
| --- | --- |
| `verdict` | `allow`, `deny`, `rewrite` (final effective verdict) |
| `source` | `rule`, `hook`, `authority`, `user`, `standalone`, `rate_limit` |
| `rule_id` | e.g. `exec.allow[1]`, `exec.ask[0]` |
| `decided_by` | Who decided (hook, authority, user) |
| `latency_ms` | Time to decide |

## `argv[].class`

| Class | Meaning |
| --- | --- |
| `static` | A binary resolved from a trusted folder, matched by name rules |
| `wrapper` | A known wrapper (`env`, `command`, `exec`, `nice`, `nohup`, `time`, `timeout`, `xargs`) that was unwrapped |
| `dynamic` | Dynamic code: never inherits classes, network limited to `hosts`, no secrets |
| `project_executable` | A binary from an agent-writable place, governed by `project_executables` |

## Human telemetry records

When recording is on, human records hold only `command`, `cwd`, `started_at`, `ended_at` and `exit_code`.
