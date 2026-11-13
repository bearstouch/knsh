# Command-line interface

The `knsh` binary wraps the API. Every command takes `--json` for machine-readable output.

| Command | Endpoint | Purpose |
| --- | --- | --- |
| `knsh agent [--profile <p>] [--agent <name>] -- <cmd>` | `user.sock` | Start an agent CLI inside an envelope |
| `knsh run` | — | Run a line through the engine (endpoint and options to be specified) |
| `knsh history` | `user.sock` | Query records |
| `knsh undo`, `knsh redo` | `user.sock` | Undo or redo a change |
| `knsh checkpoints` | `user.sock` | List checkpoints and states |
| `knsh events` | `user.sock` | Stream events |
| `knsh approvals` | `user.sock` | List pending asks |
| `knsh approve <request_id>` | `user.sock` | Approve an ask; `knshd` shows Touch ID or password prompt |
| `knsh policy check` | `user.sock` | Dry-run a line against policy |
| `knsh policy edit` | `user.sock` | Edit a policy file; saving needs Touch ID or password |
| `knsh profile use <profile>` | `user.sock` | Select a local profile; needs Touch ID |
| `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` | `user.sock` | Trust an authority; needs Touch ID or password |
| `knsh forget [--session <id> \| --since <date>] [--with-checkpoints]` | `user.sock` | Delete records and optionally checkpoints |
| `knsh daemon install` | — (launchd) | Install and load the `knshd` launch agent (see below) |
| `knsh daemon uninstall` | — (launchd) | Unload the `knshd` launch agent and remove its property list; engine data is kept |

## Daemon installation

`knshd` runs only as a launchd user agent ([process model](../02-architecture/process-model.md)); `knsh daemon`
installs and removes it without talking to `knshd`.

- `knsh daemon install` uses the `knshd` binary in the same directory as the running `knsh` (after resolving
  symlinks). It prepares the engine directories, writes `~/Library/LaunchAgents/knsh.knshd.plist` (owner-only,
  atomically), unloads any loaded `knsh.knshd` job and loads the new one into the user's GUI domain (`gui/<uid>`).
  Running it again replaces and reloads the definition. It fails with status 1 if run as root, `knshd` is missing,
  `HOME` is unusable, a socket path does not fit a Unix socket address, or launchd refuses the job.
- `knsh daemon uninstall` unloads the job (stopping `knshd`) and removes the property list. It succeeds when nothing
  is installed. Records, checkpoints and configuration are kept (`knsh forget` deletes them).
- The property list declares `user.sock` and `agent.sock` (mode `0600`) and the control service, starts `knshd` on
  demand (`RunAtLoad` false) and restarts it after a crash (`KeepAlive` → `Crashed`).

## Forget

`knsh forget` calls [`records.forget`](user-socket.md#recordsforget) and prints the number of records deleted
(`{"deleted": n}` with `--json`).

- At least one of `--session <id>` and `--since <date>` is required; with both, a record must match both. Without
  one, or with a malformed value, it is a usage error (status 2) and nothing is sent.
- `--since` takes a UTC date `YYYY-MM-DD` (from midnight UTC) or an engine timestamp `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`.
- `--with-checkpoints` is passed on. Until checkpoints exist (phase 3) `knshd` answers `-32005`: `knsh forget` says so,
  deletes nothing and exits with 1.

## Shell invocation

| Invocation | Behaviour |
| --- | --- |
| `knsh` interactive on a terminal, outside any envelope | Human session in integration mode |
| `knsh -c '…'` inside an envelope | Agent client: forwards to the supervisor over `agent.sock` |
| `knsh -c '…'` non-interactive outside any envelope | Supervised under the `unattended` profile |
| `sh`, `bash`, `zsh` shims inside an envelope | Routed to `knsh -c` |

`knsh` first classifies its argv as a shell invocation, before any subcommand parsing (KNSH-009): no arguments;
`argv[0]` starting with `-` (login shell, e.g. `-knsh`); or a first argument that is a short option cluster built from
`-c`, `-i` and `-l`, or `--login`, `-` or `--`. These follow bash's invocation syntax: options end at the first operand,
`-` or `--`; with `-c` the first operand is the command line and the rest become `$0`, `$1`, …. Any other short
option is a usage error. So `knsh -c 'history'` runs a shell line, never `knsh history`.

## Argument syntax

Commands are parsed by an in-house parser (no third-party CLI crate); the same declarations generate the help.

- Commands take long options only: `--flag`, `--option <value>` or `--option=<value>`. A separate value may not start
  with `-` (`--profile --json` is a missing value); use `--option=-x` for such a value. An empty value is missing.
- Every command accepts `--json` and `--help`. `--help` prints help generated from the declarations and exits with 0.
- `--` ends option parsing. Commands that take a child command (`knsh agent`) require it after `--` and pass everything
  after the first `--` through unchanged, byte for byte.
- Usage errors exit with status 2, print the offending flag or argument on stderr and run nothing: an unknown option,
  a missing or unexpected value, an option given twice, a missing required option or argument, an extra argument, an
  unknown command, a command group without its subcommand, or a flag, value or argument that is not UTF-8 (only argv
  after `--` and shell operands may hold arbitrary bytes).
