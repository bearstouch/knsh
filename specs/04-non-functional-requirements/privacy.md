# Privacy

Local and private by default: recording is opt-in for humans, redacted before storage, and never leaves the machine.

## Recording defaults

| Data | Human sessions | Agent sessions |
| --- | --- | --- |
| Command records | Off by default | On by default |
| Output | Off by default | Off by default |
| Denials and approvals | Not applicable: humans are never denied | Always recorded, without output |

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-PRIV-01 | Everything must stay on the machine. The engine must make no network requests of its own; the proxy only forwards traffic for sessions. |
| NFR-PRIV-02 | Redaction must run before anything is stored or emitted. |
| NFR-PRIV-03 | `knsh forget --session <id>` or `--since <date>` must delete records; `--with-checkpoints` deletes their checkpoints too. |
| NFR-PRIV-04 | Engine files must be readable by the user only, denied to every envelope and command, and excluded from Spotlight and Time Machine. |
| NFR-PRIV-05 | A recording session must set `KNSH_RECORDING=1` and report `recording` in `session.info`, so prompts and clients can show it. |
| NFR-PRIV-06 | Records must hold no secret values. |
| NFR-PRIV-07 | Pre-images of sensitive files (`.env*`, `*.pem`, `*.key`, `id_*`) must be kept for 24 hours at most. |
| NFR-PRIV-08 | The agent-command corpus must use no user telemetry; any future export must be opt-in and show the user every line before sharing ([corpus](../07-testing/agent-command-corpus.md)). |

## Storage encryption

Records rely on FileVault plus user-only permissions: they hold no secret values, output recording is off by default, and encrypting SQLite would need a third-party library. Checkpoints are the real exposure, because deleted secret files persist; that is mitigated by NFR-PRIV-07 and `knsh forget --with-checkpoints` (decision 5 in [decisions](../09-reference/decisions.md)).
