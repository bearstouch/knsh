# KNSH-042 — Grants

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Policy | M (3) | [KNSH-040](KNSH-040-rule-matching-and-precedence.md) | `knsh-core` | FR-POL-60, FR-POL-61, FR-POL-62 |

**Description.** As a user or authority, I want time-limited grants on top of a profile ("allow `git push` in this
session for one hour"), so that repeated approvals are not needed. Scope: grant model (`id`, `scope` session|profile,
rule pattern, `expires_at`), evaluation with an injected clock, list and revoke operations in the pure core;
persistence in `knshd`'s state store is wired in KNSH-074; creation authorisation (authority or Touch ID) in
KNSH-071/262.

**Acceptance criteria**
- [x] A matching unexpired grant turns an `ask` into `allow` with `decision.source` reflecting the grant; it never
  overrides a `deny` or a fixed deny.
- [x] Expired grants never match; expiry uses the injected `Clock`. (Core takes `now: Timestamp`, read by `knshd`
  from `knsh_platform::Clock`; that wiring lands with KNSH-071/074.)
- [x] Session-scoped grants match only their session; profile-scoped grants match sessions using that profile.
- [x] Revoke by ID removes the grant immediately; unknown ID is an error.
- [x] Grants never relax dynamic-code clamps.

**Unit tests**
- `grant_turns_ask_into_allow`.
- `grant_never_overrides_deny`.
- `expired_grant_does_not_match`.
- `session_grant_does_not_apply_to_other_session`.
- `revoked_grant_stops_matching`.
- `grant_does_not_lift_dynamic_clamp`.

**Notes.** — The grant model in [../05-models/grant.md](../05-models/grant.md) includes a `rule` field that the
original spec implies but does not name; confirm it there.
