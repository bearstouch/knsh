# Recording and history

`knshd` keeps a record of the commands that run, and you query it with `knsh history`. Agent commands are recorded by default; your own commands are recorded only if you turn it on.

## What is recorded

| | Your own sessions | Agent sessions |
| --- | --- | --- |
| Commands | Off until you turn it on | On |
| Output | Off | Off (you can turn it on per profile) |
| Denials and approvals | Not applicable, you are never denied | Always recorded, without output |

Everything is redacted before it is stored: any [secret](secrets.md) value is replaced by a marker such as `«redacted:npm-token»`. Records never hold secret values.

## Turn on recording for your own shell

Add this to `~/.config/knsh/config.toml`:

```toml
[recording]
human = true
```

Only an explicit `human = true` turns it on. If the file is missing, says `false`, or can't be read, recording stays off. A file that can't be read is mentioned once on stderr, and your shell starts anyway.

With recording on, each command line you run is sent to `knshd` when its prompt returns: the command, the folder it started in, when it started and ended, and its exit status. Notes:

- `knsh` can't see keystrokes. A prompt that has been waiting for 5 seconds counts as idle.
- `exit` and a line still running when the shell closes aren't recorded.
- A line longer than 64 KiB isn't recorded.
- Recording never slows or blocks your shell. If `knshd` can't be reached, the lines are dropped quietly and `knsh` tries again at the next line.
- With recording off, `knsh` never starts `knshd`.

Recording needs the service: run `knsh daemon install` once ([Getting started](../getting-started.md#start-the-background-service)).

## Look at your history

```sh
knsh history                                   # the newest 100 records
knsh history --limit 20
knsh history --text cargo                      # commands containing "cargo" (case-sensitive)
knsh history --since 2026-11-14 --until 2026-11-20
knsh history --session <session-id>
knsh history --json                            # one JSON object per line
```

Records are listed newest first. Each line shows when it started, the session, who ran it (`human` or `agent:<name>`), how it ended (`exit 0`, `signal 9`, or `-` if it hasn't finished), and the command.

`--since` and `--until` take a UTC date (`2026-11-14`, meaning midnight UTC) or a full timestamp such as `2026-11-14T09:30:00Z`. Filters combine: a record must match all of them.

Text from records is always printed safely: control characters and bidirectional marks are shown as visible escapes such as `\n` or `\e`, so a command can never rewrite your terminal when you read it. `--json` output escapes the same characters.

## Watch events live

```sh
knsh events                       # stream until you press Ctrl-C
knsh events --session <id>
knsh events --session <id> --since 42   # replay buffered events after #42, then stream
```

Each line shows the time, session, sequence number, event and a summary (for example a command's exit status, a folder change, or a state change). `--json` prints one JSON object per event.

If events are lost because you read too slowly, the stream says so with a `lost` line (or `events.lost` in JSON). The engine keeps the last 10,000 events of each session.

`knsh history` and `knsh events` only connect to the service: they never start or install it. If they can't reach it, they say so and point you to `knsh daemon install`.

## Delete history

```sh
knsh forget --session <session-id>
knsh forget --since 2026-11-01
knsh forget --session <id> --since 2026-11-01     # both must match
knsh forget --since 2026-11-01 --with-checkpoints
```

`knsh forget` needs at least one of `--session` and `--since`, and prints how many records it deleted. `--with-checkpoints` also deletes the [checkpoints](undo.md) of those records, which you should do when files you want gone (such as `.env` files an agent deleted) may be in them.

## How long records are kept

Records are kept for 30 days by default, or until the store reaches 2 GB, whichever comes first. A profile can change the number of days with `retention_days` (1 to 36500) in its `[recording]` section. Cleanup runs when the service starts and then hourly.

When output recording is on, `knsh` keeps up to 1 MB per stream, then the start and the end.

## Privacy

- Everything stays on your Mac. `knsh` makes no network requests of its own.
- The history lives in `~/Library/Application Support/knsh/`, readable by you only, hidden from every sandbox, and excluded from Spotlight and Time Machine.
- The history is not encrypted by `knsh`; it relies on FileVault and file permissions. That is acceptable because records hold no secret values and output isn't recorded by default.
