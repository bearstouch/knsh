# Writing hooks

Hooks let the user add their own checks to agent commands. They run in the supervisor, before policy, for `command.proposed`. Format: [../05-models/hook.md](../05-models/hook.md). Behaviour: [../03-functional-requirements/hooks.md](../03-functional-requirements/hooks.md).

## Example registration

```toml
[[hooks]]
event = "command.proposed"
match = { binary = ["rm", "git"] }
run = "~/.config/knsh/hooks/guard.sh"
timeout_ms = 2000
```

## Contract

| Aspect | Rule |
| --- | --- |
| Input | The event as JSON on stdin (redacted) |
| Output | A verdict on stdout: `allow`, `deny`, `ask`, `rewrite`, `annotate` |
| No output | Exit 0 is allow, exit 2 is deny |
| Errors and timeouts | Deny; there is no way to fail open |
| Order | Declared order; the first `deny` stops the chain; later hooks see rewritten lines |
| Privileges | The user's, outside any sandbox |

## Safety rules for hook authors

- Hook input contains agent-controlled text. Treat it as untrusted and **never pass it to a shell**.
- Keep hooks fast: their run time is added to every matching command and reported per record (the performance target for decisions excludes hooks).
- A rewrite cannot contain a redaction marker's real value; lines with markers cannot be rewritten.
- A malicious hook installed by the user is outside the threat model; review hooks as you would any code running with your privileges.

Envelopes cannot read or write the hook configuration, so an agent cannot register or edit a hook.
