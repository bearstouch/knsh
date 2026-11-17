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
| `knsh deny <request_id>` | `user.sock` | Deny an ask ([below](#approvals)) |
| `knsh policy check` | `user.sock` | Dry-run a line against policy |
| `knsh policy edit <profile>` | `user.sock` | Edit a policy file; saving needs Touch ID or password ([below](#policy-edit)) |
| `knsh policy grant (--session <id> \| --profile <p>) --for <duration> <rule>` | `user.sock` | Allow a command for a limited time; needs Touch ID or password ([below](#grants)) |
| `knsh policy grants` | `user.sock` | List the live grants |
| `knsh policy revoke <grant_id>` | `user.sock` | Revoke a grant at once |
| `knsh profile use <profile>` | `user.sock` | Run sessions paused by expired pushed policy under a signed local profile; needs Touch ID or password ([below](#profile-use)) |
| `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` | `user.sock` | Trust an authority; needs Touch ID or password ([below](#authority-trust)) |
| `knsh forget [--session <id> \| --since <date>] [--with-checkpoints]` | `user.sock` | Delete records and optionally checkpoints |
| `knsh shell install` | — (`/etc/shells`) | Add `knsh` to `/etc/shells` after asking, so `chsh` accepts it (see below) |
| `knsh daemon install` | — (launchd) | Install and load the `knshd` launch agent (see below) |
| `knsh daemon uninstall` | — (launchd) | Unload the `knshd` launch agent and remove its property list; engine data is kept |
| `knsh --version` | — | Print the version and, in an advisory build, the advisory label (see below) |

## Agent

`knsh agent [--profile <p>] [--agent <name>] [--json] -- <cmd…>` (KNSH-056, FR-AGT-01) calls
[`session.start_agent`](user-socket.md#sessionstart_agent) on `user.sock` with the command after `--`, its working
directory and its whole environment, its own stdin, stdout and stderr passed as descriptors, and waits. `knshd` runs
the CLI in an envelope on those streams; `knsh agent` runs nothing itself.

- It exits as the CLI did: its exit code, or 128 + `n` when signal `n` ended it. The session has ended by then.
- `--json` prints one line once the CLI has exited: `{"session_id", "agent_id", "profile", "parent_session_id",
  "exit_code", "signal"}`. Without it nothing is printed besides the CLI's own output.
- The actor is `--agent`, or derived by `knshd` from the command (`claude` → `claude-code`, FR-AGT-02).
- `--profile` or `--agent` outside `[A-Za-z0-9._-]{1,64}` is a usage error (status 2). A command that cannot be found
  (a path with `/`, or a name on `PATH`) exits with 127 (`command not found`). A command, directory or environment
  that is not UTF-8 or holds NUL exits with 1. Nothing is sent in these cases.
- A refusal exits with 1 and says why on stderr: no sandbox (`-32005`), a profile looser than the enclosing session's
  (`-32003`), an unknown profile or a command `knshd` cannot run (`-32602`), or a CLI that could not be started or
  whose `knshd` connection was lost (`-32603`).
- Killing `knsh agent` closes its connection, and `knshd` then stops the CLI's process group.
- **Limit (KNSH-057):** the CLI runs in a process group of `knshd`, not in the terminal's foreground group.
  Terminal-generated signals (Ctrl-C with `ISIG` on, `SIGWINCH`) reach `knsh agent`, not the CLI; agent CLIs run the
  terminal in raw mode and read Ctrl-C as input.

## Approvals

`knsh approvals`, `knsh approve <request_id>` and `knsh deny <request_id>` (KNSH-066, FR-AUTH-40 to FR-AUTH-43) call
[`approval.list`, `approval.approve` and `approval.deny`](user-socket.md#approvals) on `user.sock`.

- `knsh approvals` prints each pending ask as a line with its request ID, session, agent, matched rule (or hook) and
  `timeout_at`, then the command and its directory, escaped ([terminal safety](#terminal-safety)); `No pending
  asks.` when there are none. `--json` prints each request object as the API returns it, one per line.
- `knsh approve` says on stderr that the prompt is on the Mac's screen, then waits for `knshd`'s Touch ID or
  password prompt. It asks nothing on the terminal itself and has no option to skip the prompt (FR-AUTH-42).
- `knsh deny` answers at once; no prompt.
- On success they print `Approved request <id>.` or `Denied request <id>.`; `--json` prints `{"request_id",
  "verdict"}`.
- A request ID that is not 26 ULID characters is a usage error (status 2) and nothing is sent. A refusal exits with 1
  and says why on stderr: not authenticated (`-32001`), already timed out (`-32002`), cancelled (`-32011`), already
  answered or unknown (`-32602`).

## Policy edit

`knsh policy edit <profile>` (KNSH-065, FR-POL-41) edits `~/.config/knsh/policies/<profile>.toml`. `knshd` alone
signs and writes policy files ([integrity](../03-functional-requirements/policy.md#integrity)):

1. It calls [`policy.read`](user-socket.md#policyread) and, when the file is `invalid` (missing or bad signature, or
   an unreadable key), warns on stderr that `knshd` ignores it and that saving signs it, so the user reviews the text.
2. It writes the text (without the signature line) to a new `0600` file in `TMPDIR` and runs `$VISUAL`, else
   `$EDITOR`, else `vi`, through `/bin/sh -c '<editor> "$1"'`. The connection is closed meanwhile.
3. If the editor fails, nothing is sent. If the text is unchanged and the file is `valid`, it prints
   `No changes to profile <p>.` and sends nothing.
4. Otherwise it prints the size and the first 16 hex digits of the SHA-256 of the text (with a final newline), which
   the prompt on the Mac's screen also shows, and calls [`policy.edit`](user-socket.md#policyedit). Success prints
   `Signed and saved profile <p>.` (`--json`: `{"profile","changed"}`).

A profile name outside `[A-Za-z0-9._-]{1,64}` is a usage error (exit 2). A failed editor, a refused prompt
(`-32001`), text that does not load (`-32602`, with the loader's reason) or any other failure exits with 1; the edited
text is then kept in its temporary file and the path printed. `unattended` is built in and cannot be edited.

## Grants

`knsh policy grant`, `knsh policy grants` and `knsh policy revoke` (KNSH-073, FR-POL-60 to FR-POL-62) call the
[grant methods](user-socket.md#grants) on `user.sock`.

- `knsh policy grant (--session <id> | --profile <p>) --for <duration> <rule>` makes a grant. The rule is one argument
  (quote it: `knsh policy grant --profile web --for 2h 'git push'`), read like an `exec.allow` entry. `--for` is a
  whole number with `s`, `m`, `h` or `d` (seconds without one), from 1 s to 30 days. Exactly one of `--session` and
  `--profile`, a malformed ID, name, duration, or a rule outside 1 to 4096 bytes is a usage error (status 2); nothing
  is sent. It says on stderr that the prompt is on the Mac's screen, then waits for `knshd`'s Touch ID or password
  prompt; it asks nothing on the terminal and has no option to skip the prompt. Success prints `Granted <grant_id>
  until <expires_at>.`; `--json` prints `{"grant_id", "expires_at"}`. A refusal exits with 1 and says why on stderr.
- `knsh policy grants` prints one line per live grant: its ID, `session <id>` or `profile <name>`, `until
  <expires_at>`, `exact` for a grant made from an answer, and the rule, terminal-safe. `--json` prints one grant
  object per line.
- `knsh policy revoke <grant_id>` removes the grant at once, without a prompt, and prints `Revoked grant <id>.`, or
  that no live grant has that ID (it was unknown, revoked or expired). `--json` prints `{"revoked"}`.

## Profile use

`knsh profile use <profile>` (KNSH-072, FR-POL-51) calls [`profile.use`](user-socket.md#profileuse) on `user.sock`:
the agent sessions paused because their pushed policy expired run under the signed local profile `<profile>` and
resume.

- A name outside `[A-Za-z0-9._-]{1,64}` is a usage error (status 2); nothing is sent.
- It says on stderr that the prompt is on the Mac's screen, then waits for `knshd`'s Touch ID or password prompt. It
  asks nothing on the terminal itself and has no option to skip the prompt.
- On success it prints `Resumed <n> agent session(s) under the local profile <profile>:` and one session ID per
  line, or `No agent session is paused by expired pushed policy; nothing changed.` `--json` prints
  `{"profile", "sessions"}`.
- A refusal exits with 1 and says why on stderr: not a signed local profile (`-32602`, with knshd's reason) or not
  authenticated (`-32001`).

## Authority trust

`knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` (KNSH-068, FR-AUTH-10) calls
[`authority.trust`](user-socket.md#authoritytrust) on `user.sock`.

- All three options are required. A team ID, identifier or version that `knshd` would refuse is a usage error
  (status 2) and nothing is sent, so no prompt appears.
- It says on stderr that `knshd` may show its Touch ID or password prompt, naming the authority, then waits. It asks
  nothing on the terminal and has no option to skip the prompt.
- Success prints `Trusted <identifier> (team <team>, version <v> or later).`, with `, replacing the previous
  authority` when another one was trusted, or `Already trusted: …` when nothing changed. `--json` prints the result
  object.
- A refusal exits with 1 and says why on stderr: not authenticated (`-32001`), or a trust record that cannot be read
  or written (`-32603`, nothing changed).

## Version and the advisory label

`knsh --version` prints `knsh <version>` on the first line and exits with 0. Every phase 1 build is advisory
([roadmap](../01-overview/roadmap.md)) and prints a second line saying so: no security guarantees, and not for running
agents unattended. `hello` reports the same with `advisory: true` ([handshake](handshake.md)), and the repository
README carries the same warning (KNSH-024). `--version` is a root option and must be the only argument: anything after
it is a usage error (exit 2), and `knsh <command> --version` is an unknown option.

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

## History

`knsh history [--session <id>] [--since <date>] [--until <date>] [--text <text>] [--limit <n>]` (KNSH-023) reads
records with [`records.query`](user-socket.md#recordsquery) and prints the newest `n` matching records (default 100,
at most 100,000), **newest first**.

- The filters are the API's: `--session` one session; `--since` records started at or after, `--until` records started
  before, each a UTC date `YYYY-MM-DD` (midnight UTC) or an engine timestamp; `--text` a case-sensitive substring of
  the command (at most 4096 bytes). They combine with AND. A malformed value is a usage error (status 2) and nothing
  is sent.
- The API pages oldest first, so the command reads every matching page (1000 records per call) and keeps only the
  newest `n` in memory. A page whose `next_cursor` does not advance is a protocol error (status 1), never a loop.
- Text output is one line per record: `started_at  session_id  actor  status  command`, where `actor` is `human` or
  `agent:<agent_id>` and `status` is `exit <n>`, `signal <n>` or `-`. `--json` prints each record object exactly as
  the API returns it (same field names), one object per line.

## Events

`knsh events [--session <id>] [--since <seq>]` (KNSH-023) subscribes with
[`events.subscribe`](user-socket.md#eventssubscribe) and prints each event as it arrives, until interrupted.

- `--since <seq>` replays the session's buffered events after `seq` first and needs `--session` (sequence numbers
  count one session's events); without it, or with a value that is not a whole number, it is a usage error (status 2).
- Text output is one line per event: `ts  session_id  #seq  event  summary` (the exit status and command for
  `command.finished`, the directory for `cwd.changed`, `from -> to` for `session.state_changed`, the profile for
  `session.started`, otherwise the `data` object). `--json` prints each notification's `params` (the event envelope
  plus `subscription_id`) as one JSON object per line, and flushes after each.
- Events the subscription loses ([`events.lost`](user-socket.md#eventssubscribe)) are reported in the stream, in
  order: `{"event": "events.lost", "subscription_id", "session_id", "from_seq", "to_seq"}` with `--json`, a `lost`
  line otherwise. A resume older than the buffer (`gap: true`) is reported once on stderr.
- Once subscribed, reads have no deadline: an idle engine may send nothing for hours. `knshd` closing the connection
  exits with 1; a reader that goes away (`knsh events | head`) ends the command with 0.

## Reading commands and the daemon

`knsh history` and `knsh events` only connect to `user.sock`: launchd may start `knshd` on demand for the socket, but
the commands never start or install it. When the socket cannot be reached they exit with 1 and say so (`cannot reach
knshd …; see 'knsh daemon install'`), printing nothing on stdout.

## Terminal safety

Records and events carry text the engine did not author (commands, directories, event data). `knsh history` and
`knsh events` never print it raw (KNSH-023):

- Text output shows every control character (C0, DEL, C1) and every bidirectional control (U+061C, U+200E, U+200F,
  U+202A–U+202E, U+2066–U+2069) as a visible escape: `\n`, `\t`, `\r`, `\e`, `\xHH` or `\u{H…}`; a backslash is
  doubled. A record or event is therefore always one line.
- `--json` output escapes the same characters as `\uXXXX`. Each line is valid JSON and parses back to the API's value
  unchanged.

## Login shell

`knsh shell install` (KNSH-022, NFR-COMPAT-08) adds the running `knsh`, by its resolved absolute path, to
`/etc/shells`, so that `chsh -s <path>` accepts it.

- Nothing is asked or changed when `/etc/shells` already lists that path (a line equal to it, ignoring blanks and
  `#` comments).
- Otherwise it shows the exact path and asks `[y/N]` on the terminal. Only `y` or `yes` (any case) goes on; the line
  is then appended with `/usr/bin/sudo /usr/bin/tee -a /etc/shells`, which asks for the password itself. A file not
  ending in a line feed gets one first.
- It never edits `/etc/shells` without that answer: without a terminal on standard input and standard error it
  changes nothing and exits with 1. A path holding whitespace, a control character or `#` is refused before asking.
- It prints what happened and the `chsh -s` line to run (`{"shell": …, "listed": …, "added": …}` with `--json`);
  a decline exits with 0, a failure with 1. It does not run `chsh`.
- **Limit until `knsh -c` exists:** a login shell also runs `ssh host cmd`, `scp`, `rsync` and apps that read the
  login environment (`$SHELL -l -c …`), and those fail while `knsh -c` is not implemented. The text output says so
  next to the `chsh` line.

## Shell invocation

| Invocation | Behaviour |
| --- | --- |
| `knsh` interactive on a terminal, outside any envelope | Human session in integration mode |
| `knsh -c '…'` inside an envelope | Agent client: forwards to the supervisor over `agent.sock` |
| `knsh` interactive inside an envelope (session token set) | Agent client too: forwarded as an agent line reading the terminal, never a human session (FR-AGT-20) |
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
