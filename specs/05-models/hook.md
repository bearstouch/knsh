# Hook

Hooks are registered in the user's configuration (`~/.config/knsh/`, which envelopes cannot read or write). Behaviour is in [../functional-requirements/hooks.md](../functional-requirements/hooks.md).

```toml
[[hooks]]
event = "command.proposed"
match = { binary = ["rm", "git"] }
run = "~/.config/knsh/hooks/guard.sh"
timeout_ms = 2000
```

| Key | Type | Notes |
| --- | --- | --- |
| `event` | string | `command.proposed` |
| `match` | table | Optional; e.g. `binary` list |
| `run` | path | Executable to run |
| `timeout_ms` | int | Timeout; a timeout is a deny |

## Input

The `command.proposed` event ([event](event.md)) as JSON on stdin, with redacted text.

## Output

A verdict on stdout:

| Verdict | Effect |
| --- | --- |
| `allow` | No objection |
| `deny` | Refuse, with a reason shown to the agent |
| `ask` | Escalate to the authority |
| `rewrite` | Replace the line; later hooks see the new line |
| `annotate` | Add labels to the record; no decision |

If the hook prints nothing, its exit code is used: 0 is allow, 2 is deny. Any other error is a deny.
