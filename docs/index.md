# Kinetic Shell documentation

Kinetic Shell (`knsh`) is a shell for macOS that is compatible with bash and zsh. You use it as your own shell, and you use it to run AI coding agents, such as Claude Code or Codex CLI, under supervision. Every command an agent runs is checked against a policy you write, runs inside a macOS sandbox, is recorded, and, for file changes, can be undone.

[Get started](getting-started.md){ .md-button .md-button--primary } [Back to the Kinetic Shell site](/knsh/){ .md-button }

!!! warning "This build is advisory"
    This version gives no security guarantees and is not meant for running agents unattended. `knsh --version` says so too. Use it to try out the model and to watch what your agents do, and keep reviewing what they run.

## Where to start

| If you want to… | Read |
| --- | --- |
| Install `knsh` and run your first command | [Getting started](getting-started.md) |
| Use `knsh` as your daily zsh or bash | [Using knsh as your shell](guides/shell.md) |
| Keep a searchable history of what you ran | [Recording and history](guides/recording.md) |
| Run Claude Code or Codex CLI under supervision | [Agents in envelopes](guides/agents.md) |
| Decide what an agent may read, write, run and reach | [Policy profiles](guides/policy.md) |
| Approve or deny what an agent asks to run | [Approvals and grants](guides/approvals.md) |
| Control which hosts an agent can connect to | [Network access](guides/network.md) |
| Give a command a token without handing it to the agent | [Secrets](guides/secrets.md) |
| Add your own checks before an agent command runs | [Hooks](guides/hooks.md) |
| Roll back what an agent changed | [Undo and checkpoints](guides/undo.md) |
| Look up a command or an option | [Commands](reference/commands.md) |
| Find a file, setting or limit | [Files and settings](reference/configuration.md) and [Limits and defaults](reference/limits.md) |
| Work out why something is refused | [Troubleshooting](reference/troubleshooting.md) |

## How it fits together

`knsh` is three programs that work together:

| Program | What it does |
| --- | --- |
| `knsh` | The shell you type into, the command you use to start agents and manage everything, and the client that agents use to run commands. |
| `knshd` | A background service that starts on demand. It keeps the history, decides what agents may run, starts their commands and takes the checkpoints. |
| `knsh-exec` | A small helper that applies the sandbox to a command and then starts it. You never run it yourself. |

Kinetic Shell enforces and records; you decide. It evaluates the policy you wrote, and for anything that needs a decision it asks you, either with `knsh approve` or through a separate, code-signed approval app.

## Help and feedback

Found a bug or a mistake in these pages? [Open an issue](https://github.com/bearstouch/knsh/issues) or write to [mail@bearstouch.com](mailto:mail@bearstouch.com). The source is on [GitHub](https://github.com/bearstouch/knsh).
