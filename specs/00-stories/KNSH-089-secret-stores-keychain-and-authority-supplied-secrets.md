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
- [ ] Missing or inaccessible secrets return typed errors; a line that needs one is denied, not run without it. *(Typed errors: observed; denial: KNSH-092.)*
- [x] Secret values live in a type whose `Debug`/`Display` never print the value and whose memory is zeroed on drop.
- [x] No API returns a secret value to any client.

*Authority-supplied secrets*

- [x] `secrets.provide` stores the value in memory only, for the given duration.
- [ ] After expiry or `secrets.revoke`, the secret is unavailable and lines needing it are denied. *(Unavailable: observed; denial: KNSH-092.)*
- [x] Authority-supplied secrets are lost when `knshd` exits and never written to disk.
- [x] Both methods exist only on the control service.

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

**Notes.** Implemented across `knsh-core` (`SecretName`, `MAX_SECRET_VALUE_LEN`), `knsh-platform` (`SecretValue`,
zeroed on drop; the `SecretStore` trait; `KeychainSecrets`, service `knsh`; the `MemSecretStore` fake; a Keychain
reachability check in the capability probe), `knsh-proto` (`secrets.provide` and `secrets.revoke` params and results)
and `knshd` (the secrets broker and both control methods). Spec: [control service](../06-api/control-service.md#secretsprovide),
[secret](../05-models/secret.md#lookup-knsh-089), [capabilities](../05-models/capabilities.md#probe),
[defaults and limits](../09-reference/defaults-and-limits.md).

Decisions taken here: a provided secret takes the place of a Keychain item of the same name while it lives; expiry is
the earlier of the wall-clock `expires_at` and the same duration on the monotonic clock, and an unreadable wall clock
counts as expired; at most 256 provided names, values 1 byte to 64 KiB, durations 1 s to 24 hours; `secrets: keychain`
is reported only when a Keychain lookup of a never-created item answers without an error ("not found", or the item
should someone have created it); the probe now has five sequential checks, so its worst case is 10 s (was 8 s).

**Pending (unchecked boxes):**

- *Read by `knshd` from the real Keychain:* the backend is built and unit-tested through the fake; the real read is the
  manual, ignored test `reads_a_secret_added_to_a_throwaway_service` (it needs an item added to the login keychain, so
  it never runs by default). The integration test against a temporary keychain is not written: a temporary keychain
  needs `security create-keychain` and the search list changed, which touches the user's keychain configuration.
- *"A line that needs one is denied" / "lines needing it are denied":* the broker answers typed not found or access
  denied, expired and revoked secrets are unavailable at once, and `SecretBroker::resolve` gives a line all its secrets
  or names the first missing one. No line needs a secret until injection exists (KNSH-092), which must deny with that
  name.
- The `security` steps for adding an item `knshd` can read (in the secret model) are not verified end to end.
