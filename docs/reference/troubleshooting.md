# Troubleshooting

## `cannot reach knshd … see 'knsh daemon install'`

`knsh history`, `events` and the other commands that talk to the background service only connect to it; they never install it. Run:

```sh
knsh daemon install
```

If it was installed before and stopped working after you moved or updated the programs, run it again: it replaces and reloads the launch agent. It uses the `knshd` that sits beside the `knsh` you run it with, so keep `knsh`, `knshd` and `knsh-exec` in one folder.

`knsh daemon install` fails if you run it as root, if `knshd` isn't next to `knsh`, or if launchd refuses the job (the message says which).

## A command is denied with exit status 126

A denied command always prints the reason on stderr and saves it in the record. Look it up:

```sh
knsh history --json --limit 1
```

The record's decision names who decided and which rule. Typical reasons:

| Reason | What to do |
| --- | --- |
| `exec.default` | No rule matched and the profile's default is `ask` or `deny`. Add the command to `exec.allow`, `exec.ask` or `exec.deny`. |
| `exec.project_executables` | The program is in a place the agent can write (`node_modules/.bin`, `./scripts`). Set the option to `allow` or `ask` if you trust it. |
| `exec.deny[n]` | A deny rule matched. Deny always beats allow. |
| `approvals.irreversible` | The command can't be undone (a push, a deploy). Approve it, or set `approvals.irreversible`. |
| `secrets.env[n]` | The command would receive a secret, so it asks. |
| A hook name such as `hooks[0]` | One of your [hooks](../guides/hooks.md) denied it, or failed, or timed out. |
| Timed out waiting for approval | Nobody answered within 90 seconds. Answer with `knsh approve`, or raise the agent's tool timeout so the answer has time. |
| Rate limit | The same line was denied 5 times in a minute. Wait 10 minutes, or fix what the agent keeps trying. |
| Paused, or held | The session is paused (for example, its pushed policy expired). See `knsh profile use`. |

A program in `/usr/local/bin` or `/opt/homebrew/bin` matches name rules, but one installed elsewhere, such as under `~/.nvm` or `~/.cargo/bin`, does not. Add its folder to `exec.trusted_folders`.

## A command that should be allowed asks anyway

- The line may hold **dynamic code** (`bash -c`, `eval`, `python -c`, or an argument built from an expansion). Those are limited, and if any part can't be matched to an allow rule, it asks.
- It may be **irreversible**, or would receive a **secret**. Those ask even when `exec.allow` allows the command.
- Rules match the program's trusted name. `./git` or `node_modules/.bin/eslint` never match a name rule.

## The agent can't reach its own API, or any host

- `network.mode` defaults to `none`. A preset adds the agent's hosts, but doesn't turn the network on. Set `mode = "allowlist"`.
- Look at what was refused: `knsh events` shows `proxy.denied` events with a reason, and the command's record lists the hosts it contacted.
- A tool that ignores proxy settings (`git` over SSH, older Node) can't connect at all. Use an HTTPS remote, or a current Node.
- Hosts that carry anything other than TLS need `network.non_tls_hosts` as well. See [Network access](../guides/network.md).

## The agent's own tools fail inside the envelope

Probably the agent CLI is using its own sandbox, which macOS can't nest. Check that `knsh agent` didn't warn about it, and see [Turn off the agent's own sandbox](../guides/agents.md#turn-off-the-agents-own-sandbox). Programs that sandbox themselves (Chromium, Playwright, `swift build`) need to be listed under `exec.trusted_tools`.

## Commands don't show up in `knsh history`

- Agent commands appear only if they go through `knsh`. Commands run with `/bin/bash -c`, a script's `#!/bin/bash` line, or a full path skip the per-command decision (they are still sandboxed). See [Make sure the agent uses knsh](../guides/agents.md#make-sure-the-agent-uses-knsh).
- Your own commands appear only with `[recording] human = true`, and only in hosted zsh or bash, not [native mode](../guides/native-mode.md).
- A line over 64 KiB, `exit`, and the line that was running when the shell closed aren't recorded.

## `knsh policy edit` doesn't save

- If the profile doesn't load, the message names the key and line. Your text is kept in a temporary file whose path is printed.
- A refused prompt (you cancelled Touch ID, or the password was wrong) exits with 1. Edit again; nothing was saved.
- Profile names use 1 to 64 letters, digits, `.`, `_` and `-`.
- A profile that was edited by hand, or whose signature can't be verified, is ignored by `knshd`. Open it with `knsh policy edit` again, review it, and save it to sign it.

## Undo refuses

`knsh undo` lists every conflicting path and why. See [When undo refuses](../guides/undo.md#when-undo-refuses). The usual fix is to undo later changes first, or to use `--force` if you accept losing what is on disk now.

## Prompts appear in the wrong place, or not at all

`knsh approve`, `knsh policy edit`, `knsh policy grant`, `knsh profile use` and `knsh authority trust` all say on stderr that a prompt is on your Mac's screen. The prompt comes from `knshd`, not from your terminal, so it appears on the Mac's display. If Touch ID is unavailable, it falls back to your password.

## My login shell breaks `ssh host command` or `scp`

Programs that run commands through your login shell with `-c` are treated as unattended lines and are denied or restricted. Don't set `knsh` as your account's login shell if you rely on these; start `knsh` from your terminal's own settings instead. See [Using knsh as your shell](../guides/shell.md#use-knsh-as-your-login-shell).

## Start with a clean slate

- Remove the service: `knsh daemon uninstall`. Your data stays.
- Delete your history and checkpoints: `knsh forget --since 1970-01-01 --with-checkpoints`.
- To remove everything, uninstall the service, then delete `~/Library/Application Support/knsh/` and `~/.config/knsh/`.

## Still stuck?

[Open an issue](https://github.com/bearstouch/knsh/issues) or write to [mail@bearstouch.com](mailto:mail@bearstouch.com). Say what you ran, the exact message, and the output of `knsh --version`. Don't paste secrets or private command lines.
