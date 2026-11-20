# Output modes

Callers of `exec.run` choose how much output comes back, to save an agent's context.

| Mode | Returns |
| --- | --- |
| `full` | Everything, up to 1 MB per stream (beyond it, the head and tail the capture kept) |
| `truncate` | The first `max_bytes` of each stream (default 64 KiB); at most the first 512 KiB of a stream over 1 MB, the part kept without a gap |
| `head_tail` | The first and last `lines` lines of each stream (default 20), with a count of the lines skipped between them; a stream of at most `2 × lines` lines comes back whole as its head |
| `errors_only` | stderr as in `full`, the exit code and the last 20 lines of stdout, with a count of the stdout lines skipped |
| `ref` | Sizes, line counts and the `record_id`; the caller fetches ranges later with `records.output` (only when the session records output) |

Every mode also returns both streams' sizes and line counts. The exact result fields, how text that is not UTF-8 is
shown, and how an answer too large for one frame is cut are in [agent socket](../06-api/agent-socket.md#result).
The default mode comes from the profile's `output.mode` (`full` unless set).

| ID | Requirement |
| --- | --- |
| FR-OUT-01 | `exec.run` must support the modes above, selected with `output.mode`. |
| FR-OUT-02 | Each profile must set a default mode. |
| FR-OUT-03 | Through `knsh -c`, output must go straight to the caller's terminal or pipes as usual; output modes apply only to `exec.run`. |
| FR-OUT-04 | Output from `knsh -c` must never cross the API: the client hands its stdio descriptors to the supervisor, which attaches them to the command directly. |
| FR-OUT-05 | The engine must not summarise output itself. |
| FR-OUT-06 | Output returned to callers must be redacted ([secrets](secrets.md#redaction)). |

Status (KNSH-053): FR-OUT-01 to FR-OUT-05 are implemented for `exec.run`, `exec.start` and `exec.wait`. FR-OUT-06 is
implemented as a hook every captured chunk passes through before it is kept, returned, stored or emitted; it redacts
the session's secrets since KNSH-091 ([secrets](secrets.md#redaction-on-every-output-path-knsh-091)).
