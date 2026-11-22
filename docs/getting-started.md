# Getting started

This page takes you from nothing to a working setup: installing `knsh`, starting the background service, running your own shell through it, and starting an agent in a sandbox.

!!! warning "This build is advisory"
    It gives no security guarantees and is not for running agents unattended. Run `knsh --version` to see the label.

## Requirements

- macOS 14 Sonoma or later, on Apple silicon.
- zsh (included with macOS) or bash. Homebrew's bash 5 works too.
- To run agents, the agent CLI itself, such as Claude Code or Codex CLI.

## Install

Build `knsh` from source with the Rust toolchain (`rustup` installs the right version on first use):

```sh
git clone https://github.com/bearstouch/knsh.git
cd knsh
cargo build --release --workspace --offline --locked
```

The three programs end up in `target/release/`: `knsh`, `knshd` and `knsh-exec`. Keep them together in one folder. `knsh` looks for its siblings next to itself. Put that folder on your `PATH`, or copy the three programs somewhere that is:

```sh
mkdir -p ~/.local/bin
cp target/release/knsh target/release/knshd target/release/knsh-exec ~/.local/bin/
knsh --version
```

`knsh --version` prints the version and, on an advisory build, a second line saying so.

## Start the background service

Recording, agents and undo all need `knshd`. Install it once as a launch agent for your user:

```sh
knsh daemon install
```

This writes `~/Library/LaunchAgents/knsh.knshd.plist` and loads it. launchd starts `knshd` the first time something needs it and stops it again after ten idle minutes. Running the command again replaces and reloads the definition, which is what you do after moving or updating the programs.

To remove it later:

```sh
knsh daemon uninstall
```

This stops the service and removes the launch agent. Your history, checkpoints and settings stay where they are until you delete them (see [Recording and history](guides/recording.md#delete-history)).

## Use it as your shell

Type `knsh` in any terminal. You get your own zsh (or bash), started by `knsh`, with your startup files running exactly as before. Nothing is blocked or changed, and nothing is recorded unless you turn recording on. See [Using knsh as your shell](guides/shell.md) for login shells and the settings.

## Start your first agent

Agents run in an *envelope*: a macOS sandbox that denies everything by default. What the agent may do is set by a [policy profile](guides/policy.md).

1. Create a profile. Policy files are signed by `knshd`, so you write them through `knsh`:

    ```sh
    knsh policy edit starter
    ```

    Your editor (`$VISUAL`, then `$EDITOR`, then `vi`) opens. Paste this, save and close:

    ```toml
    name = "starter"
    preset = "claude-code"

    [fs]
    write = ["${PROJECT}", "${TMPDIR}"]

    [exec]
    allow = ["git status", "git diff", "git log", "ls", "cat", "rg", "grep"]
    ask   = ["git push", "rm *"]
    deny  = ["sudo *"]
    default = "ask"

    [network]
    mode = "allowlist"   # the preset adds the agent's own API host
    ```

    A prompt appears on your Mac's screen showing the size and a short fingerprint of the file. Approve it with Touch ID or your password, and `knsh` prints `Signed and saved profile starter.`

2. Start the agent in that profile, from your project folder:

    ```sh
    knsh agent --profile starter -- claude
    ```

    Use `codex` and `preset = "codex-cli"` for Codex CLI.

3. Whenever the agent wants to run something your profile doesn't allow, it asks. In another terminal:

    ```sh
    knsh approvals        # list what is waiting
    knsh approve <id>     # approve one; a prompt appears on your screen
    knsh deny <id>        # deny one
    ```

    If you use an approval app, it shows these requests instead (see [Approvals and grants](guides/approvals.md)).

4. When the agent has changed things you don't want, undo them:

    ```sh
    knsh checkpoints
    knsh undo --checkpoint <checkpoint-id>
    ```

!!! tip "Turn off the agent's own sandbox"
    macOS cannot put a sandbox inside another sandbox. If Claude Code or Codex CLI sandbox their own commands, that fails inside an envelope. `knsh agent` warns you when it sees this. See [Agents in envelopes](guides/agents.md#turn-off-the-agents-own-sandbox).

## The core ideas

| Idea | What it means |
| --- | --- |
| **Human or agent** | Every command belongs to exactly one of the two. Humans are only observed, never blocked. Agent commands are decided before they run. |
| **Envelope** | The macOS sandbox an agent CLI runs in. It starts with nothing allowed and gets only what its profile and preset grant. |
| **Policy profile** | A signed TOML file that says what an agent may read, write, run and reach, and what needs your approval. |
| **Ask** | A command the profile says needs a decision. It waits for you (or your approval app) and is denied if nobody answers in 90 seconds. |
| **Checkpoint** | A record of what a command or agent edit changed, so you can undo it. |
| **Record** | A history entry for a command: what ran, where, when, how it ended and how it was decided. |

## What is stored on your Mac

| What | Where |
| --- | --- |
| Settings, hooks and policy files | `~/.config/knsh/` |
| History, checkpoints, sockets, compiled profiles | `~/Library/Application Support/knsh/` |
| Launch agent | `~/Library/LaunchAgents/knsh.knshd.plist` |
| Secrets you add | Your Keychain, under the service name `knsh` |

All of it is readable by your user only, hidden from every sandbox, and excluded from Spotlight and Time Machine. Nothing leaves your Mac: `knsh` makes no network requests of its own. See [Files and settings](reference/configuration.md) for the full list.
