# KNSH-118 — Spike: user-presence check for approvals on Linux

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Authority | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | — (spike) | FR-AUTH-41, FR-POL-41, NFR-SEC-04 |

**Description.** As the engine on Linux, I need an equivalent of Touch ID or password checked inside `knshd`, so that
approvals, policy edits, grants and authority trust cannot be faked by the CLI.

Scope: evaluate polkit, PAM conversation from `knshd`, and fingerprint daemons, with and without a desktop session.
Output: a decision and spec update, not production code.

**Acceptance criteria**
- [ ] Written comparison of options with their guarantees and failure modes.
- [ ] Decision recorded in `09-reference/decisions.md`; `platform-support.md` gains an "Authentication" row.
- [ ] If no option meets NFR-SEC-04, the spec states which features are unavailable on Linux.

**Unit tests**
- None (spike). Prototype code, if any, is thrown away.

**Notes.** The specs do not cover user presence on Linux at all — this spike resolves that gap.
