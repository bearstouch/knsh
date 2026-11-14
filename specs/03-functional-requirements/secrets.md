# Secrets

A **secret** is a named value stored in the Keychain (service `knsh`), or supplied by the authority with `secrets.provide` for a limited time and held only in memory. The definition format is in [../05-models/secret.md](../05-models/secret.md).

## Injection

| ID | Requirement |
| --- | --- |
| FR-SEC-01 | A secret must be injected as an environment variable only into supervised lines that match its `inject_for` patterns. |
| FR-SEC-02 | Lines that would receive a secret must ask unless a grant covers them. |
| FR-SEC-03 | A line that receives a secret must have its network narrowed to that secret's `hosts`, so the value can only be sent where it is meant to go. |
| FR-SEC-04 | Dynamic code must never receive secrets. |
| FR-SEC-05 | Profiles must limit process information to the command's own sandbox (proposed by decision 8, pending acceptance; a process group cannot be enforced safely), so other processes cannot read the injected environment or arguments. |
| FR-SEC-06 | `secret.injected` must report the secret's name and the command, never the value; the record's `secrets_injected` lists names only. |
| FR-SEC-07 | Authority-supplied secrets must be held only in memory, for the time given, and must be lost when `knshd` exits. `secrets.revoke` must remove them at once. |

Anything an injected line runs can read the secret, including npm lifecycle scripts. Prefer short-lived, narrowly scoped tokens supplied by the authority; presets can rewrite publishing commands to skip lifecycle scripts where the tool allows it.

## Redaction

| ID | Requirement |
| --- | --- |
| FR-SEC-10 | Redaction must replace the exact value and its base64, URL-encoded and hex forms, across chunk boundaries, with `«redacted:<name>»` (for example `«redacted:npm-token»`). |
| FR-SEC-11 | Redaction must run before anything is stored or emitted, including text sent to hooks and the authority. |

Redaction misses transformed values and files written to disk; it is a convenience, not a control.
