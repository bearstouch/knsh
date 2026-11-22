# Limits and defaults

The limits you are most likely to meet. Where a limit can be changed, the table says how.

## Service

| What | Value |
| --- | --- |
| Background service idle exit | 10 minutes with nothing to do (launchd starts it again on demand) |
| Simultaneous connections | 64 |
| First message from a client | 10 seconds, then the connection is closed |
| Approval timeout | 90 seconds, then the command is denied. Keep the agent's own tool timeout longer. |
| Hook timeout | 1 to 60000 ms per hook, set in `timeout_ms` |
| Hooks | At most 32, output at most 256 KiB |
| Repeated denials | 5 denials of the same line in 60 seconds: denied outright for 10 minutes |
| Grants | 1 second to 30 days; at most 1,024 live at once |
| Message size | 1 MB |

## Recording

| What | Value |
| --- | --- |
| Your own commands | Off. Turn on with `[recording] human = true`. |
| Agent commands | On, output off |
| Retention | 30 days or 2 GB, whichever comes first. Days per profile: `recording.retention_days` (1 to 36500) |
| Recorded output | 1 MB per stream, then the start and the end |
| Event history | The last 10,000 events of each session |
| A recorded line of your own | At most 64 KiB |
| History query | Up to 100,000 records; `--limit` defaults to 100 |
| Idle prompt | 5 seconds |

## Agent commands

| What | Value |
| --- | --- |
| Agent command line | 1 MiB. A longer one is treated as dynamic code. |
| Nesting in a line (quotes, substitutions, compound commands) | 32 levels. Deeper is treated as dynamic code. |
| Time limit | A command that passes its time limit gets `SIGTERM` to its process group, then `SIGKILL` after 2 seconds. |
| Long-running event | After 30 seconds |
| Commands of one line running at once (native mode) | 256 |
| Output returned to an agent calling the engine directly | `full` 1 MB per stream; `truncate` 64 KiB by default (1 byte to 1 MiB); `head_tail` 20 lines by default (1 to 10,000); `errors_only` the last 20 lines of stdout |

## Network proxy

| What | Value |
| --- | --- |
| Listener | One local port on `127.0.0.1`, chosen when the service starts |
| Handshake | 10 seconds |
| Connecting to the destination | 10 seconds, then the client gets `504` |
| Idle and total tunnel time | Closed after 5 minutes without data, and after 4 hours in all |
| Simultaneous connections | 512 |
| Request line / header | 4096 bytes / 8192 bytes, at most 64 headers and 16 KiB in all |

## Checkpoints

| What | Value |
| --- | --- |
| Retention | 5 GB per volume, 200 per root or 7 days, whichever comes first |
| Sensitive files (`.env*`, `*.pem`, `*.key`, `id_*`) | Old versions are kept at most 24 hours |
| Fingerprinted files | Under 64 MiB |
| Plain-copy checkpoints (non-APFS volumes) | 50 MB per change |
| Excluded folders | `node_modules`, `target`, `.venv`, `dist`, `build` by default (`checkpoints.exclude`) |
| Files in one checkpoint | 65,536, then it is marked uncertain |

## Secrets

| What | Value |
| --- | --- |
| Value size | 1 byte to 64 KiB |
| Secrets supplied by an approval app at once | 256, for 1 second to 24 hours |

## Policy files

| What | Value |
| --- | --- |
| Profile size | 1 MiB |
| `extends` chain | 8 profiles |
| Path in a profile | 4096 bytes |
| Trusted folders by default | `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` |
| Pushed profiles | 64, each at most 1 MiB |

## Native mode

Native mode has size caps that bash itself doesn't have. Past a cap, the command fails with an error instead of running out of memory.

| What | Value |
| --- | --- |
| Line you type, or a file you `source` | 1 MiB |
| Nesting of functions, loops and `eval` | 1,000 levels |
| Arithmetic nesting | 1,024 levels |
| `${…}` and `$((…))` inside each other, and nested braces | 256 levels |
| Brace expansion of one word | 1,048,576 words |
| File matches for one pattern | 1,048,576 |
| Output of one `$(…)` | 64 MiB |
| One `printf` | 64 MiB of output; widths up to 1 MiB |
| One `read` line | 16 MiB |
| One `mapfile` | 64 MiB |
| File descriptor numbers in redirections | 0 to 255 |
| Finished background jobs remembered | 1,024 |
| History list | `HISTSIZE` (500 by default), at most 100,000 entries |
| Undo steps while editing a line | 1,000, with a kill ring of 10 |
| Completion matches | 65,536; more than 100 are listed only after asking |

## Defaults at a glance

| Setting | Default |
| --- | --- |
| `fs.read` | everything except `fs.deny` |
| `exec.default`, `exec.project_executables`, `approvals.irreversible` | `ask` |
| `network.mode` | `none` |
| `exec.bash` | `/bin/bash` (3.2) |
| `exec.mode` | `line` |
| Hosted shell | The bash `$SHELL` names, otherwise `/bin/zsh` |
| Terminal marks | On when `knsh`'s output is a terminal |
