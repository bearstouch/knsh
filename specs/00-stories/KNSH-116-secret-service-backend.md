# KNSH-116 — Secret Service backend

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Secrets | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knsh-platform` | platform-support.md (Secrets), FR-SEC-01 – FR-SEC-07, NFR-SUP-07 |

**Description.** As a Linux user, I want secrets and the engine's private keys stored in the Secret Service, or only
authority-provided when it is absent, so that secret handling matches macOS.

**Acceptance criteria**
- [ ] Secrets, the policy signing key and the authority trust record use the Secret Service when available.
- [ ] Without it, `hello` reports `secrets: none` (or authority-only), and Keychain-dependent features report
      unavailable rather than storing keys in plain files.
- [ ] The D-Bus client is hand-written or uses a justified dependency (NFR-SUP-02).

**Unit tests**
- `secret_roundtrip_via_fake_service`
- `missing_service_reports_none`
- `signing_key_never_written_to_plain_file`

**Notes.** Restricting access to `knshd` only (the Keychain guarantee on macOS) is not achievable with the Secret
Service alone. Spec gap: state the weaker Linux guarantee in `platform-support.md`.
