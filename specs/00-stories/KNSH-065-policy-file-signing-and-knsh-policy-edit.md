# KNSH-065 — Policy file signing and `knsh policy edit`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-039](KNSH-039-policy-profile-model-and-loader.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knsh-platform`, `knshd`, `knsh` | FR-POL-40 – FR-POL-42, FR-HOOK-07 |

**Description.** As a user, I want policy files signed by `knshd` and editable only after Touch ID, so that an agent
or other process cannot change my policy unnoticed.

**Acceptance criteria**
- [ ] On first use, `knshd` creates a signing key in a Keychain item whose access control allows only `knshd`'s code
      signature. *(Implemented: the key is created on the first signature with `SecItemAdd` and the default access
      list in the login keychain, user interaction disabled, never overwritten; observed only through the fake key
      store. The item's access control from the real `knshd` is pending the manual integration test below.)*
- [x] `knsh policy edit <name>` opens the file in `$EDITOR`. On save, `knshd` asks for Touch ID or password, then signs.
      *(Observed with the scripted prompt in `knshd`'s tests; the real prompt from `knshd` and the editor round trip
      are pending a manual run.)*
- [x] A file with a missing or bad signature is ignored and reported with `policy.invalid`. Sessions using it do not
      fall back to another profile.
- [x] The signature covers the exact bytes of the file. Any change invalidates it.
- [x] Signing and verification use CommonCrypto through `knsh-platform`.

**Unit tests**
- `accepts_correctly_signed_file` — FR-POL-40 (`knsh-platform`, `signing`).
- `ignores_file_with_bad_signature_and_emits_invalid` — FR-POL-42 (`knshd`, `supervisor`).
- `ignores_unsigned_file` — FR-POL-42 (`knsh-platform`, `signing`).
- `any_byte_change_invalidates_signature` — FR-POL-40 (`knsh-platform`, `signing`).
- `refuses_to_sign_without_authentication` — FR-POL-41 (`knshd`, `policy_edit`).

**Integration tests**
- **Pending (manual):** the Keychain item stays readable after a `knshd` update with the same Developer ID, and is
  unreadable by an ad-hoc-signed binary (claim C5).
- **Pending (manual):** `knsh policy edit` against an installed `knshd`: the editor round trip, the Touch ID or
  password prompt with the profile and hash in it, and a cancelled prompt leaving the file unchanged. The ignored test
  `macos::keychain::tests::creates_then_reads_a_throwaway_item` exercises the Keychain calls on a throwaway item.

**Notes**
- Spec gap: the signature algorithm (HMAC-SHA256 with a Keychain secret, or an asymmetric key) and where the
  signature is stored (a sidecar file or an embedded trailer) are not specified. Decide and record them in
  [policy](../03-functional-requirements/policy.md).
- From KNSH-026 ([C5 results](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7), proposed decision 11): use the file-based keychain from a Developer ID-signed
  `knshd`, with Keychain user interaction disabled. Any same-user process can overwrite the item; code outside the team
  then makes `knshd`'s read fail, so a read failure on an existing key is tampering (fail closed, recover only with
  Touch ID or the password). Ad-hoc and Homebrew-from-source builds lose the key on every upgrade. The manual integration test above was
  observed on macOS 26.6 by the spike; it still needs to run against the real `knshd`.
- Spec gap, resolved ([policy integrity](../03-functional-requirements/policy.md#integrity)): HMAC-SHA-256 with a
  32-byte Keychain key, stored as an embedded trailer line (`# knsh-signature: v1 hmac-sha256 <hex>`), so text and
  signature are replaced in one atomic write. The MAC also binds the profile name. API: `policy.read` and
  `policy.edit` on `user.sock` ([user socket](../06-api/user-socket.md#policy-files)); CLI:
  [`knsh policy edit <profile>`](../06-api/cli.md#policy-edit).
- Implemented: `knsh-platform` `signing` (`PolicySigner`, `SigningKeyStore`, the trailer format, constant-time
  comparison), `macos::hmac_sha256` (`CCHmac`, RFC 4231 vectors), `macos::KeychainSigningKey` (legacy login keychain,
  user interaction disabled, `SecItemAdd` only), `testing::MemKeyStore`; `PolicyDirectory` verifies every file before
  the loader sees it (`LookupError::SignatureInvalid`, `ProfileErrorKind::SignatureInvalid`) and saves only with an
  `Authenticated` proof. `knshd`: the loader logs `policy.invalid`; the supervisor publishes `policy.invalid` on the
  session and denies the line; `policy_edit` serves `policy.read` and `policy.edit` (validate, prompt, sign, atomic
  write). `knsh`: `knsh policy edit <profile>`.
- Existing unsigned profile files are ignored after this change until saved once with `knsh policy edit`.
- Pending (manual, claim C5): whether a same-user process outside envelopes can plant the Keychain item first with an
  access list open to all applications and a key it knows, which `knshd` would then read and trust. Envelopes cannot
  (every profile denies writes under `~/Library/Keychains`); KNSH-026 observed that a planted item with the default
  access list is unreadable by `knshd`.
- Pending follow-ups: recovery from a tampered key item (needs Touch ID and a way to replace an unreadable item),
  rollback of a file to an older signed version by a same-user process outside envelopes, and signing the hook
  configuration (FR-HOOK-07 still rests on the fixed deny of `~/.config/knsh/`).
