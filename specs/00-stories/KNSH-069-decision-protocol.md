# KNSH-069 — Decision protocol

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | `knshd`, `knsh-proto` | FR-AUTH-20 – FR-AUTH-24, FR-EVT-06, FR-LC-41 |

**Description.** As the supervisor, I want to send asks to the authority and apply its answers with strict timeouts
and cancellation, so that no command runs without a timely, matching answer.

**Acceptance criteria**
- [x] `decision.requested` carries `request_id`, `session_id`, `actor`, redacted `command`, `cwd`, `matched_rule`,
      `irreversible` and `timeout_at`. It goes only to the authority. *(Also `rewritten_from` and `hook`, as
      `approval.list` shows them. `irreversible` is `null` until lines are classified for it, KNSH-093. Never
      published as an event.)*
- [x] `decision.respond` with `allow`, `deny` or `rewrite` (with `command`), and an optional `grant {scope,
      duration_s}` and `reason`, is applied to the matching pending request. *(Only from the registered authority's
      connection; `-32003` otherwise, `-32602` for malformed params. Result `{"applied", "grant_id"}`.)*
- [x] The default timeout is **90 s**. At the timeout the request is denied, and the caller gets `-32002`. *(On the
      injected clock in tests; end to end through the orchestrator in `authority_timeout_is_32002`.)*
- [x] If the caller disconnects, `decision.cancelled` is sent and a late answer is ignored. *(Sent to the authority
      for timeouts too, with `reason: timed_out`; the `decision.cancelled` event is published as before.)*
- [x] If the authority disconnects, pending requests that have not timed out are re-sent when it reconnects.
      *(Unchanged, after the answer to `authority.register`. **Pending:** over XPC with a Developer ID-signed
      authority, as for KNSH-067 and KNSH-068.)*
- [x] An answer for an unknown or finished request ID is ignored and logged without command text.
- [x] A `grant` in the answer creates a grant (KNSH-042) with the given scope and duration. *(For the asked line;
      held in memory until KNSH-074. Every agent line is now evaluated with the live grants.)*

**Unit tests**
- `sends_request_with_all_fields` — FR-AUTH-20.
- `applies_allow_answer` — FR-AUTH-21.
- `denies_at_ninety_second_timeout_with_32002` — FR-AUTH-23 (fake clock).
- `ignores_late_answer_after_cancellation` — FR-AUTH-22.
- `resends_pending_on_reconnect` — FR-AUTH-24.
- `creates_grant_from_answer` — FR-POL-62.
- `ignores_unknown_request_id` — FR-AUTH-22.

Also: `refuses_answers_not_from_the_authority` (`knshd`, `decisions`); `authority_timeout_is_32002` and
`authority_grant_allows_the_line_again` (`knshd`, `supervisor`); `notifies_the_named_connection` and
`sends_pending_requests_after_registering` (`knshd`, `control`); `answer_grant_rule_is_the_asked_command` and
`answer_grant_rule_refuses_lines_it_cannot_express` (`knsh-core`, `policy::grant`); `reads_each_verdict`,
`refuses_malformed_answers` and `cancelled_and_result_round_trip` (`knsh-proto`, `decision`).

**Notes**
- Spec gap: `decision.respond` had no result. Decided: `{"applied", "grant_id"}`; an ignored answer is a success
  with `applied: false`, not an error, since the authority did nothing wrong by answering late.
- Spec gap: a `grant` names only a scope and a duration, not the rule it allows. Decided: the asked line itself,
  only when it is one simple command whose every word is known (no expansion, space or `*`) and holds no secret;
  otherwise no grant, and the `allow` stands. Recorded in [grant](../05-models/grant.md). Decided in review: such a
  grant is exact (`Grant::exact`): it does not cover the same command with more arguments (no FR-POL-16 extension),
  so `rm -r build` never grants `rm -r build /`.
- Decided while implementing: a `grant` is accepted only with `allow` (`-32602` otherwise); `duration_s` is 1 s to
  30 days and `reason` at most 1024 bytes ([defaults and limits](../09-reference/defaults-and-limits.md)).
- Decided while implementing: `decision.cancelled` is also sent directly to the authority (as a notification), for
  timeouts as well as departed callers, so it can withdraw its prompt whether or not it subscribes to events.
- Grants are held in memory until the state store keeps them (KNSH-074); `policy.grants` and `policy.revoke` arrive
  with KNSH-071.
