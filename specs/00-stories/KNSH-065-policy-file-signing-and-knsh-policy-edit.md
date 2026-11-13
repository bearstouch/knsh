# KNSH-065 — Policy file signing and `knsh policy edit`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-039](KNSH-039-policy-profile-model-and-loader.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knsh-platform`, `knshd`, `knsh` | FR-POL-40 – FR-POL-42, FR-HOOK-07 |

**Description.** As a user, I want policy files signed by `knshd` and editable only after Touch ID, so that an agent
or other process cannot change my policy unnoticed.

**Acceptance criteria**
- [ ] On first use, `knshd` creates a signing key in a Keychain item whose access control allows only `knshd`'s code
      signature.
- [ ] `knsh policy edit <name>` opens the file in `$EDITOR`. On save, `knshd` asks for Touch ID or password, then signs.
- [ ] A file with a missing or bad signature is ignored and reported with `policy.invalid`. Sessions using it do not
      fall back to another profile.
- [ ] The signature covers the exact bytes of the file. Any change invalidates it.
- [ ] Signing and verification use CommonCrypto through `knsh-platform`.

**Unit tests**
- `accepts_correctly_signed_file` — FR-POL-40.
- `ignores_file_with_bad_signature_and_emits_invalid` — FR-POL-42.
- `ignores_unsigned_file` — FR-POL-42.
- `any_byte_change_invalidates_signature` — FR-POL-40.
- `refuses_to_sign_without_authentication` — FR-POL-41.

**Integration tests**
- **Pending (manual):** the Keychain item stays readable after a `knshd` update with the same Developer ID, and is
  unreadable by an ad-hoc-signed binary (claim C5).

**Notes**
- Spec gap: the signature algorithm (HMAC-SHA256 with a Keychain secret, or an asymmetric key) and where the
  signature is stored (a sidecar file or an embedded trailer) are not specified. Decide and record them in
  [policy](../03-functional-requirements/policy.md).
