# Hooks

A hook is a program of yours that looks at each agent command before it runs and can allow, deny, ask about, rewrite or label it. Use hooks for rules a pattern can't express: "never delete anything outside the project", "add `--dry-run` to deploys", "tag everything that touches `terraform`".

Hooks apply to agent commands only. Your own shell is never hooked.

## Register a hook

Hooks live in `~/.config/knsh/config.toml`, the folder agents can neither read nor write:

```toml
[[hooks]]
event = "command.proposed"
match = { binary = ["rm", "git"] }
run = "~/.config/knsh/hooks/guard.sh"
timeout_ms = 2000
```

| Key | Meaning |
| --- | --- |
| `event` | Required. Only `command.proposed` exists: an agent line is about to be decided. |
| `match` | Optional. `binary` is a list of command names (no `/`). The hook runs when any command in the line has one of those names. Without `match`, it runs for every agent line. Dynamic code (`eval`, `bash -c`) matches every list, since what it runs isn't known. |
| `run` | Required. An absolute path, or one starting with `~/`. It must be an existing regular file **inside `~/.config/knsh/`**, owned by you, not writable by anyone else, and executable. |
| `timeout_ms` | Required. 1 to 60000. A hook that takes longer is killed and counts as a denial. |

You can register up to 32 hooks. They run in the order they're written. The file is read for every agent line, so an edit applies to the next command.

## What a hook receives

The hook is started directly (not through a shell), outside any sandbox, with your privileges, from the folder `/`, and with an environment of only `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and `HOME`. It receives one JSON object on standard input, with secrets already redacted:

```json
{"event": "command.proposed", "session_id": "01J…", "actor": {"kind": "agent", "agent_id": "claude-code"},
 "data": {"command": "rm -rf build", "cwd": "/Users/me/project", "rewritten_from": null}}
```

## What a hook answers

Either nothing, or one JSON object on standard output:

| Member | Meaning |
| --- | --- |
| `verdict` | Required. `allow`, `deny`, `ask`, `rewrite` or `annotate`. |
| `reason` | Optional, up to 1024 bytes. For `deny`, it is shown to the agent. |
| `command` | Required for `rewrite` only: the new line. |
| `labels` | Required for `annotate` only: 1 to 16 labels, each 1 to 64 characters from `A-Z a-z 0-9 . _ : -`. |

| Verdict | Effect |
| --- | --- |
| `allow` | No objection. Policy still decides. |
| `deny` | The command is refused, with your reason. |
| `ask` | Send it to you (or the approval app) for a decision. |
| `rewrite` | Replace the line. Later hooks, and policy, see the new line. |
| `annotate` | Add labels to the record. No decision. |

If the hook prints nothing: exit code 0 means `allow` and exit code 2 means `deny`. **Any other outcome is a denial**: another exit code, a crash, invalid output, more than 256 KiB of output, a timeout, or a hook that can't be started. There is no way for a hook to fail open.

## Failing closed

Problems with the setup also deny commands rather than skip the hook:

| Problem | Result |
| --- | --- |
| No `config.toml`, or no `hooks` | No hooks. |
| `config.toml` can't be read or isn't valid | **Every** agent command is denied. |
| One hook is wrongly written (unknown key, missing key, a `run` that is relative, missing, outside `~/.config/knsh/`, writable by others, or not executable) | That hook denies every command it would match. |

## Writing a safe hook

- **The input is untrusted.** It contains text the agent controls. Never pass it to a shell, `eval` it, or paste it into a command.
- Keep the hook file where only you can write it, as required. Don't have it run files from the project or other places an agent can write.
- Keep hooks fast: their time is added to every matching command and saved in the record.
- A line you rewrite is evaluated again from the start, and your hook runs on it too. Answer `allow` for a line you already rewrote: a second rewrite denies the line.
- A line containing a redaction marker can't be rewritten, because the marker isn't the real value.
- Hooks run with your privileges. Review them like any program you run.

## A small example

`~/.config/knsh/hooks/guard.sh`:

```sh
#!/bin/sh
# Deny an "rm" aimed at /etc; print nothing (allow) for everything else.
if /usr/bin/grep -Eq '"command": *"rm [^"]*/etc' ; then
  printf '{"verdict":"deny","reason":"rm of system paths is not allowed"}'
fi
```

Make it owner-only and executable, and keep it inside `~/.config/knsh/`:

```sh
mkdir -p ~/.config/knsh/hooks
chmod 700 ~/.config/knsh/hooks/guard.sh
```

This only matches text. For anything more than a quick check, parse the JSON properly with a program of your choice, and remember the hook's `PATH` is only `/usr/bin:/bin:/usr/sbin:/sbin`.

See which hooks ran for a command in its record: `knsh history --json` lists each hook and how long it took.
