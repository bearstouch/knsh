# KNSH-111 — In-house SHA-256 and HMAC replacing CommonCrypto

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Platform | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knsh-platform` | NFR-SUP-07, FR-POL-40, FR-CKP-09 |

**Description.** As the engine on Linux, I need hashing and policy signatures without CommonCrypto, so that
checkpoint identities and policy signatures work without a new crate.

Scope: SHA-256 and HMAC-SHA-256 (or whatever primitive the macOS signature uses — keep them identical so formats do
not diverge) behind the existing hashing trait. Alternative: link the system's libcrypto through `libc`-style FFI;
choose and justify in the crate docs.

**Acceptance criteria**
- [ ] Outputs match the NIST test vectors and the macOS backend bit for bit.
- [ ] Policy files signed on Linux verify with the Linux key store; the format is the same as on macOS.
- [ ] Constant-time comparison is used for signature checks.
- [ ] No new third-party crate, or a written justification if system libcrypto is linked.

**Unit tests**
- `sha256_matches_nist_vectors`
- `hmac_sha256_matches_rfc4231_vectors`
- `signature_check_is_constant_time`
- `macos_and_linux_hash_identically` (shared vectors)

**Notes.** Hand-writing cryptography is a risk; prefer linking a vetted system library if the review agrees. Record
the decision in `09-reference/decisions.md`.
