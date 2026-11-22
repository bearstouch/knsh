# Approvals and grants

When a profile says a command needs a decision (`ask`), the command waits. You answer it from the command line, or from a separate approval app. If nobody answers within 90 seconds, the command is denied, and the agent sees the denial and its reason.

## Answer from the command line

In another terminal (never in the agent's):

```sh
knsh approvals
```

Each pending request is one line with its request ID, session, agent, the rule that asked, and when it times out, followed by the command and its folder. With `No pending asks.` there's nothing waiting.

```sh
knsh approve <request-id>
knsh deny <request-id>
```

- **`knsh approve`** says on stderr that the prompt is on your Mac's screen. The system's Touch ID or password prompt shows the exact command. The request is approved only after you authenticate. `knsh approve` has no option to skip this.
- **`knsh deny`** answers at once, with no prompt.

On success you see `Approved request <id>.` or `Denied request <id>.`.

The prompt is always shown by `knshd`, never on the agent's terminal, because an agent driving that terminal could otherwise answer it itself.

If `knsh approve` fails, it says why: you aren't authenticated, the request already timed out, it was cancelled because the agent's command was interrupted, or it was already answered. A request ID is 26 characters long; anything else is a usage error.

## Grants: say yes for a while

If you're asked about the same thing over and over, grant it for a limited time instead:

```sh
knsh policy grant --profile web-app --for 2h 'git push'
knsh policy grant --session <session-id> --for 30m 'npm publish'
```

- Exactly one of `--session` (one session) and `--profile` (every session using that profile) is required.
- `--for` is a whole number followed by `s`, `m`, `h` or `d` (seconds with no letter), from 1 second to 30 days.
- The rule is one argument. Quote it. It reads like an `exec.allow` entry: `git push` also covers `git push origin main`.
- Making a grant needs Touch ID or your password. There's no way to skip it.

On success you see `Granted <grant-id> until <time>.`

```sh
knsh policy grants              # list live grants: id, scope, expiry, rule
knsh policy revoke <grant-id>   # remove one at once, no prompt
```

What a grant can and can't do:

- A grant only answers an `ask`. It never overrides a `deny`, and never opens the engine's protected folders.
- It covers commands that would receive a [secret](secrets.md) or reach an approval host, if its rule covers them.
- It doesn't widen what a command can reach: dynamic code stays limited, and never gets secrets or approval hosts.
- Grants survive a restart of `knshd`, until they expire.
- If the time can't be read, no grant applies.

## An approval app (the authority)

You can run a separate app that presents requests, instead of using `knsh approve`. In Kinetic Shell's terms it is the *authority*: one code-signed app that approves or denies commands, can rewrite one, sets grants, pauses and takes over sessions, supplies short-lived secrets and can push policy.

`knsh` works without one. When you use one:

1. The app must be signed with a Developer ID or App Store signature, with the hardened runtime on and no debugging entitlement.
2. Trust it once:

    ```sh
    knsh authority trust --team-id ABCDE12345 --identifier com.example.approver --min-version 1.0
    ```

    All three options are required. It needs Touch ID or your password, and prints `Trusted <identifier> (team <team>, version <v> or later).` If another app was trusted before, it is replaced. The trust record sits in the Keychain where only `knshd` can read it.

3. From then on, while the app is connected, requests go to it instead of `knsh approvals`. `knshd` and the app each verify the other's signature on every connection. Only one authority can be connected at a time. If it disconnects, waiting requests are sent again when it reconnects (if they haven't timed out).

Pushed policy: an authority can send a policy that expires. When it does, agent sessions using it are paused, and their commands are held, until the authority returns or you choose a local profile:

```sh
knsh profile use web-app
```

This runs the paused sessions under your signed local profile `web-app` and resumes them. It needs Touch ID or your password and lists the sessions it resumed. If there aren't any, it says so and changes nothing.

## Rewrites

A hook or an authority can **rewrite** a command, replacing it with a safer one (for example, adding `--dry-run`). The new line is checked again, once. A second rewrite is refused and the line is denied. A line that contains a redaction marker is never rewritten, because the marker isn't the real value.

## Rate limiting

An agent that keeps trying a denied command is slowed down: five denials of the same line within a minute make that line denied outright for ten minutes.
