# Defaults and limits

| Setting | Default or limit | Configurable | Source |
| --- | --- | --- | --- |
| `knshd` idle exit | 10 minutes | — | [process model](../02-architecture/process-model.md) |
| `knshd` concurrent connections | 64 over both sockets; further connections are closed on accept | — | [process model](../02-architecture/process-model.md) |
| First message (`hello`) timeout | 10 s after connecting, then the connection is closed | — | [process model](../02-architecture/process-model.md) |
| Write to a client | 30 s blocked, then the connection is closed | — | [process model](../02-architecture/process-model.md) |
| Shutdown grace | 5 s for in-flight requests, then connections are closed | — | [process model](../02-architecture/process-model.md) |
| Authority decision timeout | 90 s, then deny | Yes; set shorter than the agent CLI's tool timeout | [authority](../03-functional-requirements/authority.md) |
| Hook timeout | `timeout_ms` per hook (example 2000), 1 to 60000 | Per hook | [hook](../05-models/hook.md) |
| Hooks registered | At most 32 | — | [hook](../05-models/hook.md) |
| Hook stdout | At most 256 KiB; `reason` 1024 bytes; 16 labels of 64 bytes | — | [hook](../05-models/hook.md) |
| Rate limit | 5 denials of the same normalised line in 60 s → denied for 10 minutes | — | [hooks](../03-functional-requirements/hooks.md) |
| `command.long_running` | 30 s | Yes (`Limits` in `knshd`; no configuration file key yet) | [command lifecycle](../03-functional-requirements/command-lifecycle.md) |
| Timeout kill grace | At `timeout_s`, `SIGTERM` to the line's process group, then `SIGKILL` after 2 s if anything is left; the group is killed once more before its leader is reaped | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md#spawning-knsh-051) |
| Supervised line watch | Checked every 1 ms at first, backing off to every 50 ms: timeouts and `command.long_running` fire at most 50 ms late | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md#spawning-knsh-051) |
| Proxy listener | One ephemeral port on `127.0.0.1` only, chosen at `knshd` start | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy handshake | 10 s for the whole handshake (request head, or SOCKS5 greeting to request), then the connection is closed | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy request head | Request line 4096 bytes, header line 8192 bytes, 64 header lines, 16 KiB in all; over a limit is `431` | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy connect | 10 s to reach the destination, then `504` (SOCKS5 `0x06`) | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy tunnel timeouts | Closed after 5 minutes without a byte either way, and 4 hours after it opened | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy TLS ClientHello | After the success answer, 10 s (a fresh handshake timeout) and at most 20 KiB of records for a complete ClientHello of at most 16 KiB; otherwise the tunnel is refused (`timeout`, `not_tls`) | — | [network proxy](../03-functional-requirements/network-proxy.md#tls-server-name-check-knsh-061) |
| Proxy connections | 512 at once; further connections are closed on accept and reported | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| Proxy credentials | 65,536 live at once; a command whose credentials cannot be issued does not start | — | [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059) |
| `session.idle` | 5 s at a human prompt | — | [sessions](../03-functional-requirements/sessions.md) |
| Human recording | Off | `[recording] human` in `~/.config/knsh/config.toml` | [terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session) |
| Hosted shell (integration mode) | The bash `$SHELL` names, else `/bin/zsh`; an invalid choice starts `/bin/zsh` | `[shell] hosted` in `~/.config/knsh/config.toml` | [terminals and shells](../08-integrations/terminals-and-shells.md#login-shell) |
| Terminal marks (OSC 7, OSC 133) | On when `knsh`'s standard output is a terminal | — | [terminals and shells](../08-integrations/terminals-and-shells.md#terminal-markup) |
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
| `truncate` bytes | 64 KiB by default, 1 to 1 MiB (`output.max_bytes`) | Per call | [output modes](../03-functional-requirements/output-modes.md) |
| `head_tail` lines | 20 by default, 1 to 10,000 (`output.lines`) | Per call | [output modes](../03-functional-requirements/output-modes.md) |
| Captured `exec.run` answer | One frame: output text is cut to fit (`cut_to_fit`) | — | [agent socket](../06-api/agent-socket.md#result) |
| `command.output` chunk | At most 8 KiB; published only for the first 1 MB of each stream | — | [event](../05-models/event.md) |
| Output drain after the line ends | 250 ms for a leftover writer, then the capture is final | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md#output-capture-knsh-053) |
| Started lines per session (`exec.start`) | 64 not yet collected by `exec.wait` | — | [agent socket](../06-api/agent-socket.md#execstart-execwait-execkill) |
| Frame payload | 1 MB | — | [wire format](../06-api/wire-format.md) |
| JSON nesting | 32 levels | — | [wire format](../06-api/wire-format.md) |
| JSON integers | ±2^53 | — | [wire format](../06-api/wire-format.md) |
| Agent command line (bash parser) | 1 MiB (macOS `ARG_MAX`, and the 1 MB frame payload the line arrives in), checked before tokenising; over it the line is dynamic (`input_too_large`) | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md) (KNSH-028, KNSH-032) |
| Bash tokens per line (parser) | 65,536, counted over the line and every substitution body parsed in it; lexing stops at the first token over it, and the line is dynamic (`too_many_tokens`). Bounds the token lists and tree, which 1 MiB of one-letter words would otherwise make about a million tokens long; agent lines hold tens to a few hundred | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md) (KNSH-032) |
| Bash quote and substitution nesting (lexer) | 32 levels; a here-document body counts as one level, and backtick bodies count when they are parsed. Over it the line is dynamic (`nesting_too_deep`) | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md) (KNSH-028, KNSH-031, KNSH-032) |
| Bash command-list nesting (parser) | 32 levels, the same constant, reached by compound commands, function bodies and substitutions; bounds the parser's recursion. Over it the line is dynamic (`nesting_too_deep`) | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md) (KNSH-029, KNSH-030, KNSH-031, KNSH-032) |
| Function definitions analysed for call marking (parser) | 64 per line; past it no call is marked as a function call, so every call is resolved as a program | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md) (KNSH-030) |
| Content hash in post-image identity | Files under 64 MB (64 MiB, 67,108,864 bytes) | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Checkpoint retention | 5 GB per volume, 200 per root, or 7 days | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Sensitive-file pre-images | 24 hours at most | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Plain-copy checkpoints (non-APFS) | 50 MB per change (50 MiB, 52,428,800 bytes; larger changes recorded as not protected) | — | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Checkpoint excludes | `node_modules`, `target`, `.venv`, `dist`, `build` | `checkpoints.exclude` | [checkpoints](../03-functional-requirements/checkpoints.md) |
| Rewrites per line | 1, by a hook or the authority alike; a second is a deny | — | [authority](../03-functional-requirements/authority.md) |
| Caller check while an ask waits | Every 100 ms, so a disconnected caller cancels its line at once (FR-LC-41) | — | [command lifecycle](../03-functional-requirements/command-lifecycle.md#the-decision-pipeline-knsh-050) |
| Grant from a `decision.respond` answer | 1 s to 30 days (`duration_s`); longer is `-32602` | — | [control service](../06-api/control-service.md#decision-protocol) (KNSH-069) |
| Grant from `policy.grant` | 1 s to 30 days (`duration_s`); rule 1 to 4096 bytes | — | [control service](../06-api/control-service.md#policygrant) (KNSH-071) |
| Secrets from `secrets.provide` | 256 names at once; value 1 byte to 64 KiB; `duration_s` 1 s to 24 hours; expired secrets dropped within about 1 s | — | [control service](../06-api/control-service.md#secretsprovide) (KNSH-089) |
| Keychain secret value | 64 KiB; a larger item is access denied | — | [secret](../05-models/secret.md#lookup-knsh-089) (KNSH-089) |
| Secret values one redactor holds | 256 KiB in total, each 1 byte to 64 KiB; a larger set is refused (at the limit about 110 MB, 400 MB while built) | — | [secrets](../03-functional-requirements/secrets.md#redaction-engine-knsh-090) (KNSH-090) |
| Bytes a redaction stream holds back | Fewer than 3 × the longest decoded form of any secret (about 4 × the longest value) | — | [secrets](../03-functional-requirements/secrets.md#redaction-engine-knsh-090) (KNSH-090) |
| Pushed policy snapshots | 64 profiles; each at most 1 MiB of text | — | [control service](../06-api/control-service.md#policyset) (KNSH-071) |
| Pushed-policy expiry check | Every 1 s: sessions on an expired snapshot are paused at most about 1 s late (their lines are denied from `expires_at` on) | — | [control service](../06-api/control-service.md#policyset) (KNSH-072) |
| `profile.use` prompt | Waits at most 120 s | — | [`profile.use`](../06-api/user-socket.md#profileuse) (KNSH-072) |
| `reason` in a `decision.respond` answer | 1024 bytes, as a hook's reason; longer is `-32602` | — | [control service](../06-api/control-service.md#decision-protocol) (KNSH-069) |
| Deprecated method lifetime | 2 engine minor releases | — | [API](../06-api/README.md) |
| Human recording | Off | Per session | [privacy](../04-non-functional-requirements/privacy.md) |
| Agent recording | Commands on, output off | Per profile, `recording.set` | [privacy](../04-non-functional-requirements/privacy.md) |
| `fs.read` | `"all"` (except deny list) | Per profile | [policy](../03-functional-requirements/policy.md) |
| `exec.default`, `exec.project_executables`, `approvals.irreversible` | `ask` | Per profile | [policy profile](../05-models/policy-profile.md#defaults) |
| `network.mode` | `none` | Per profile | [policy profile](../05-models/policy-profile.md#defaults) |
| Default `exec.run` output mode | `full` | Per profile (`output.mode`) | [policy profile](../05-models/policy-profile.md#defaults) |
| Profile `extends` chain | 8 profiles, the loaded one included; longer is an error | — | [policy profile](../05-models/policy-profile.md#loading) |
| Profile file | 1 MiB (the TOML parser's limit), refused before reading | — | [policy profile](../05-models/policy-profile.md#toml-subset) |
| Agent bash | `/bin/bash` (3.2) | Per profile | [compatibility](../04-non-functional-requirements/compatibility.md) |
| Trusted folders | `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` | Profile can add | [policy](../03-functional-requirements/policy.md) |
