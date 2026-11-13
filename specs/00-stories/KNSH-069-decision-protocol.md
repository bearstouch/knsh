# KNSH-069 — Decision protocol

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | `knshd`, `knsh-proto` | FR-AUTH-20 – FR-AUTH-24, FR-EVT-06, FR-LC-41 |

**Description.** As the supervisor, I want to send asks to the authority and apply its answers with strict timeouts
and cancellation, so that no command runs without a timely, matching answer.

**Acceptance criteria**
- [ ] `decision.requested` carries `request_id`, `session_id`, `actor`, redacted `command`, `cwd`, `matched_rule`,
      `irreversible` and `timeout_at`. It goes only to the authority.
- [ ] `decision.respond` with `allow`, `deny` or `rewrite` (with `command`), and an optional `grant {scope,
      duration_s}` and `reason`, is applied to the matching pending request.
- [ ] The default timeout is **90 s**. At the timeout the request is denied, and the caller gets `-32002`.
- [ ] If the caller disconnects, `decision.cancelled` is sent and a late answer is ignored.
- [ ] If the authority disconnects, pending requests that have not timed out are re-sent when it reconnects.
- [ ] An answer for an unknown or finished request ID is ignored and logged without command text.
- [ ] A `grant` in the answer creates a grant (KNSH-042) with the given scope and duration.

**Unit tests**
- `sends_request_with_all_fields` — FR-AUTH-20.
- `applies_allow_answer` — FR-AUTH-21.
- `denies_at_ninety_second_timeout_with_32002` — FR-AUTH-23 (fake clock).
- `ignores_late_answer_after_cancellation` — FR-AUTH-22.
- `resends_pending_on_reconnect` — FR-AUTH-24.
- `creates_grant_from_answer` — FR-POL-62.
- `ignores_unknown_request_id` — FR-AUTH-22.
