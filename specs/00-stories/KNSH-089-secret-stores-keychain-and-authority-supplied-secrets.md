# KNSH-089 — Secret stores: Keychain and authority-supplied secrets

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Secrets | L (5) | [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | `knsh-platform`, `knshd`, `knsh-proto` | FR-SEC-01, secret model, FR-SEC-07 |

**Description.** Merged from *Keychain secret store* and *Authority-supplied secrets*: they are done and validated together because both sources feed the same secrets broker and lookup tests.

*Keychain secret store.* As the secrets broker, I want to read named secrets from the Keychain (service `knsh`), using the
access-control approach validated by KNSH-026, so that values are never stored by the engine itself. Scope: read by
name, typed "not found" and "access denied" errors, values held in a zeroised buffer type, fake for tests.
Out of scope: injection (KNSH-092).

*Authority-supplied secrets.* As the authority, I want to provide a secret for a limited time and revoke it, so that short-lived
tokens can be used without storing them. Scope: `secrets.provide` (name, value, duration) and `secrets.revoke` on the
control service, memory-only storage, expiry.

**Acceptance criteria**
*Keychain secret store*

- [ ] A secret stored under service `knsh` and a given name can be read by `knshd`.
- [ ] Missing or inaccessible secrets return typed errors; a line that needs one is denied, not run without it.
- [ ] Secret values live in a type whose `Debug`/`Display` never print the value and whose memory is zeroed on drop.
- [ ] No API returns a secret value to any client.

*Authority-supplied secrets*

- [ ] `secrets.provide` stores the value in memory only, for the given duration.
- [ ] After expiry or `secrets.revoke`, the secret is unavailable and lines needing it are denied.
- [ ] Authority-supplied secrets are lost when `knshd` exits and never written to disk.
- [ ] Both methods exist only on the control service.

**Unit tests**
*Keychain secret store*

- `missing_secret_returns_not_found`
- `secret_value_debug_output_is_redacted`
- `secret_buffer_is_zeroed_on_drop`

*Authority-supplied secrets*

- `provided_secret_expires_after_duration` (FR-SEC-07)
- `revoked_secret_is_unavailable_immediately` (FR-SEC-07)
- `provided_secret_is_never_persisted`

**Integration tests**
*Keychain secret store*

- Read a test item from a temporary Keychain (pending if not runnable in CI).
