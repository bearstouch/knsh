# Commands

Every command accepts `--json` for machine-readable output and `--help` for its options.

## Summary

| Command | What it does |
| --- | --- |
| `knsh` | Your own shell (zsh, bash or native), hosted by `knsh`. |
| `knsh agent` | Start an agent CLI inside an envelope. |
| `knsh history` | List recorded commands, newest first. |
| `knsh events` | Stream events until you stop it. |
| `knsh forget` | Delete records and, optionally, checkpoints. |
| `knsh checkpoints` | List changes that can be undone. |
| `knsh undo`, `knsh redo` | Undo or redo a change. |
| `knsh approvals` | List commands waiting for a decision. |
| `knsh approve`, `knsh deny` | Answer one. |
| `knsh policy edit` | Create or change a policy profile. |
| `knsh policy grant`, `grants`, `revoke` | Allow a command for a limited time, list grants, remove one. |
| `knsh profile use` | Resume paused sessions under a local profile. |
| `knsh authority trust` | Trust an approval app. |
| `knsh daemon install`, `uninstall` | Install or remove the background service. |
| `knsh shell install` | Allow `knsh` as a login shell. |
| `knsh --version` | Print the version. |

`knsh run` and `knsh policy check` are listed in `--help` but aren't implemented yet: they say so and exit with 1.

## Options and usage errors

- Options are long: `--flag`, `--option value` or `--option=value`. A separate value can't start with `-`; write `--option=-x` for such a value. An empty value counts as missing.
- `--` ends option parsing. For commands that take a child command (`knsh agent`), the child command must come after `--` and is passed through unchanged.
- A usage error (unknown option or command, missing or extra value, an option given twice, a missing required argument, a value that isn't valid text) prints what's wrong on stderr, runs nothing, and exits with **2**.
- IDs for records, sessions, requests and checkpoints are 26 characters long. Anything else is a usage error and nothing is sent.
- Most commands talk to the background service. Commands that only read it (`history`, `events`) never start or install it; if they can't reach it, they say so and exit with 1.

## `knsh` (your shell)

```text
knsh [-cil] [<command line>] [<arg>...]
```

| Invocation | What it is |
| --- | --- |
| `knsh` on a terminal | Your own shell, started by `knsh`. |
| `knsh -l`, `knsh --login`, or started as `-knsh` | The same, as a login shell. |
| `knsh -i` | Force an interactive shell. |
| `knsh -c '…'`, a script, or piped input | A non-interactive line: treated as an agent line (see below). |

Options follow bash: they end at the first argument that isn't an option, `-` or `--`; with `-c` the first remaining argument is the command line and the rest become `$0`, `$1`, …. So `knsh -c 'history'` runs a shell line, never `knsh history`. Any other short option is a usage error.

**Non-interactive lines** are always handed to the supervisor. Inside an envelope they follow the agent's profile. Outside one, they run under the locked-down built-in `unattended` profile. See [Using knsh as your shell](../guides/shell.md).

## `knsh agent`

```sh
knsh agent [--profile <name>] [--agent <name>] [--json] -- <command>...
```

Starts the command inside an envelope and waits. Exits with the agent's exit code, or 128 + the signal number. With `--json`, prints one line when the agent exits: session ID, agent ID, profile, parent session, exit code and signal. A command that isn't found exits with 127. Refusals exit with 1 and say why. See [Agents in envelopes](../guides/agents.md).

## `knsh history`

```sh
knsh history [--session <id>] [--since <date>] [--until <date>] [--text <text>] [--limit <n>] [--json]
```

Shows the newest *n* matching records (default 100, at most 100,000), newest first. `--since` and `--until` take `YYYY-MM-DD` (UTC, from midnight) or `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`. `--text` matches part of the command, case-sensitive, up to 4096 bytes. Filters combine. Text output is one line per record: `started_at  session_id  actor  status  command`. See [Recording and history](../guides/recording.md).

## `knsh events`

```sh
knsh events [--session <id>] [--since <seq>] [--json]
```

Streams events until you press <kbd>Ctrl</kbd>-<kbd>C</kbd>. `--since` replays a session's buffered events after that sequence number first, and needs `--session`. If `knshd` closes the connection it exits with 1; if the reader goes away (`knsh events | head`) it exits with 0.

## `knsh forget`

```sh
knsh forget [--session <id>] [--since <date>] [--with-checkpoints] [--json]
```

Needs `--session`, `--since` or both (a record must match both). Prints how many records it deleted. `--with-checkpoints` also deletes their checkpoints.

## `knsh checkpoints`, `knsh undo`, `knsh redo`

```sh
knsh checkpoints [--session <id>] [--json]
knsh undo [--checkpoint] [--force] <id> [--json]
knsh redo [--checkpoint] [--force] <id> [--json]
```

`<id>` is a record ID from `knsh history`; with `--checkpoint` it is a checkpoint ID from `knsh checkpoints`. `--force` restores files that changed since, or that may be torn, losing what is there now. See [Undo and checkpoints](../guides/undo.md).

## `knsh approvals`, `knsh approve`, `knsh deny`

```sh
knsh approvals [--json]
knsh approve <request-id> [--json]
knsh deny <request-id> [--json]
```

`approve` waits for the Touch ID or password prompt on your Mac's screen and has no way to skip it. `deny` answers at once. See [Approvals and grants](../guides/approvals.md).

## `knsh policy`

```sh
knsh policy edit <profile>
knsh policy grant (--session <id> | --profile <name>) --for <duration> '<rule>'
knsh policy grants [--json]
knsh policy revoke <grant-id>
```

`edit` opens the profile in `$VISUAL`, else `$EDITOR`, else `vi`, and signing it needs Touch ID or your password. `grant` needs the same; `--for` is a number with `s`, `m`, `h` or `d`, from 1 second to 30 days. `revoke` is immediate. See [Policy profiles](../guides/policy.md) and [Approvals and grants](../guides/approvals.md).

## `knsh profile use`

```sh
knsh profile use <profile>
```

Runs the agent sessions that were paused because their pushed policy expired under the signed local profile `<profile>`, and resumes them. Needs Touch ID or your password.

## `knsh authority trust`

```sh
knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <version>
```

All three options are required. Needs Touch ID or your password. See [Approvals and grants](../guides/approvals.md#an-approval-app-the-authority).

## `knsh daemon`

```sh
knsh daemon install
knsh daemon uninstall
```

`install` uses the `knshd` that sits next to `knsh`, writes `~/Library/LaunchAgents/knsh.knshd.plist` and loads it into your user session. Running it again replaces and reloads it. It fails if run as root, if `knshd` isn't there, or if launchd refuses. `uninstall` stops the service and removes the file; your data stays. It succeeds when nothing is installed.

## `knsh shell install`

```sh
knsh shell install
```

Adds `knsh` to `/etc/shells` after you answer `y`, so `chsh -s` accepts it. It does nothing if it's already listed, needs a terminal, and never runs `chsh`. See [Using knsh as your shell](../guides/shell.md#use-knsh-as-your-login-shell).

## `knsh --version`

Prints `knsh <version>`, and on an advisory build a second line saying there are no security guarantees. It must be the only argument.

## Exit codes

For `knsh -c` and for the commands an agent runs, the exit status follows bash:

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 to 125 | The command's own exit status. |
| 126 | Found but not executable, **or denied** by policy, a hook, the approval app or rate limiting. The reason is always printed on stderr and saved in the record. `knsh -c` also exits 126 when the line didn't run, or its outcome is unknown, for any other reason (the service wasn't available, the session ended, the connection was lost). |
| 127 | Command not found. |
| 128 + *n* | Killed by signal *n*. |

The `knsh` management commands exit with 0 on success, 1 on a refusal or failure (with the reason on stderr), and 2 on a usage error.
