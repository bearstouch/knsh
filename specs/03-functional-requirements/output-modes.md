# Output modes

Callers of `exec.run` choose how much output comes back, to save an agent's context.

| Mode | Returns |
| --- | --- |
| `full` | Everything, up to 1 MB per stream |
| `truncate` | The first `max_bytes` |
| `head_tail` | The first and last `lines` lines, with a count of what was skipped |
| `errors_only` | stderr, the exit code and the last 20 lines of stdout |
| `ref` | Sizes, line counts and the `record_id`; the caller fetches ranges later with `records.output` |

| ID | Requirement |
| --- | --- |
| FR-OUT-01 | `exec.run` must support the modes above, selected with `output.mode`. |
| FR-OUT-02 | Each profile must set a default mode. |
| FR-OUT-03 | Through `knsh -c`, output must go straight to the caller's terminal or pipes as usual; output modes apply only to `exec.run`. |
| FR-OUT-04 | Output from `knsh -c` must never cross the API: the client hands its stdio descriptors to the supervisor, which attaches them to the command directly. |
| FR-OUT-05 | The engine must not summarise output itself. |
| FR-OUT-06 | Output returned to callers must be redacted ([secrets](secrets.md#redaction)). |
