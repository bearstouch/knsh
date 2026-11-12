# Command-line interface

The `knsh` binary wraps the API. Every command takes `--json` for machine-readable output.

| Command | Endpoint | Purpose |
| --- | --- | --- |
| `knsh agent [--profile <p>] [--agent <name>] -- <cmd>` | `user.sock` | Start an agent CLI inside an envelope |
| `knsh run` | — | Run a line through the engine (endpoint and options to be specified) |
| `knsh history` | `user.sock` | Query records |
| `knsh undo`, `knsh redo` | `user.sock` | Undo or redo a change |
| `knsh checkpoints` | `user.sock` | List checkpoints and states |
| `knsh events` | `user.sock` | Stream events |
| `knsh approvals` | `user.sock` | List pending asks |
| `knsh approve <request_id>` | `user.sock` | Approve an ask; `knshd` shows Touch ID or password prompt |
| `knsh policy check` | `user.sock` | Dry-run a line against policy |
| `knsh policy edit` | `user.sock` | Edit a policy file; saving needs Touch ID or password |
| `knsh profile use` | `user.sock` | Select a local profile; needs Touch ID |
| `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` | `user.sock` | Trust an authority; needs Touch ID or password |
| `knsh forget [--session <id> \| --since <date>] [--with-checkpoints]` | `user.sock` | Delete records and optionally checkpoints |

## Shell invocation

| Invocation | Behaviour |
| --- | --- |
| `knsh` interactive on a terminal, outside any envelope | Human session in integration mode |
| `knsh -c '…'` inside an envelope | Agent client: forwards to the supervisor over `agent.sock` |
| `knsh -c '…'` non-interactive outside any envelope | Supervised under the `unattended` profile |
| `sh`, `bash`, `zsh` shims inside an envelope | Routed to `knsh -c` |
