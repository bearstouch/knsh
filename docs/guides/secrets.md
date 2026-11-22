# Secrets

Agents often need a token, such as an npm token to publish. Giving the agent the token itself is risky. `knsh` lets you name a secret, and injects it only into the commands you choose, only after you've agreed, and limits where that command can connect. The agent never sees the value, and the value is removed from everything `knsh` stores or prints.

## Define a secret in a profile

```toml
[secrets.env]
NPM_TOKEN = { secret = "npm-token", inject_for = ["npm publish"], hosts = ["registry.npmjs.org"] }
```

| Part | Meaning |
| --- | --- |
| `NPM_TOKEN` | The environment variable the command receives. |
| `secret` | The name of the secret in the Keychain, or supplied by an approval app. |
| `inject_for` | Command patterns that receive it. Written like `exec.allow` patterns. |
| `hosts` | The **only** hosts such a command can reach while it holds the secret. An entry with no hosts leaves the command no network. |

## Add a secret to the Keychain

Secrets live in your login Keychain under the service name `knsh`, with the secret's name as the account. `knshd` has to be allowed to read the item. Items created by other programs trust only that program, so create it with `knshd` allowed:

```sh
security add-generic-password -s knsh -a npm-token -T "$(command -v knshd)" -w
```

`-w` at the end makes `security` ask you for the value, so it isn't left in your shell history.

On macOS this may also need the item's partition list to name `knshd`. That second step asks for your keychain password:

```sh
security set-generic-password-partition-list -S apple-tool:,teamid:<TEAM> -s knsh -a npm-token
```

`knshd` never shows the Keychain's "Allow access" dialog. An item it isn't allowed to read counts as *access denied*, and `knsh` never creates, changes or deletes a Keychain item itself. A value must be 1 byte to 64 KiB.

!!! note
    Setting up Keychain access for a notarized, Developer ID–signed `knshd` hasn't been verified end to end yet in this build. If the line is denied with a reason that names the secret, check the access list of the item.

An approval app can also supply a secret for a limited time (up to 24 hours). It is held in memory only, is lost when `knshd` exits, and takes the place of a Keychain item with the same name while it's live.

## What happens when a command needs a secret

1. A command that matches `inject_for` **asks**, even when `exec.allow` allows it, unless a [grant](approvals.md#grants-say-yes-for-a-while) covers it. Under the `unattended` profile, where nobody can answer, it's denied.
2. Once approved, the value is looked up and put in the command's environment under the variable you named, replacing any variable of that name already there.
3. The command's network is narrowed to the hosts the secret lists (and the profile also allows). It gets no `network.loopback` ports either.
4. Everything the command prints, and everything stored about it, has the value replaced by `«redacted:npm-token»`. This covers the value and its base64, URL-encoded and hex forms, even when it is split across chunks of output.
5. The record lists the secret's *name*, never its value.

A command that needs a secret it can't get is denied, never run without it. It is also denied if the secret's variable is one `knsh` sets itself (proxy settings, `DYLD_*`), or the value contains a NUL byte.

## What never gets a secret

- **Dynamic code** (`bash -c`, `eval`, `python -c`, …). It is never given a secret, even if you approved it, and isn't asked about one.
- A line that couldn't be read reliably.
- Other processes on your Mac: a command's sandbox hides other processes' environment and arguments.

## Know the limits

Anything the receiving command runs can read the secret, including scripts it starts. A package manager's lifecycle scripts, such as npm's, run with the token in their environment. Prefer short-lived, narrowly scoped tokens, and keep `hosts` as small as it can be.
