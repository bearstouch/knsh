# KNSH-071 — Control methods: `session.*`, `policy.*`, `recording.set`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-042](KNSH-042-grants.md), [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | `knshd`, `knsh-proto` | FR-SES-02, FR-POL-01, FR-POL-50, FR-POL-53, FR-POL-60 – FR-POL-62, [control service](../06-api/control-service.md) |

**Description.** As an authority, I want to manage sessions, push policy, manage grants and change recording, so
that I can supervise agents end to end.

**Acceptance criteria**
- [x] The `session.*` methods create, end, pause, resume, take control and release control of any session. *(Any
      agent session: `session.create`, `session.end`, `session.pause`, `session.resume`, `session.take_control`,
      `session.release_control`, plus `session.list`. A human session is `-32003` for all but `session.list`
      (FR-SES-22).)*
- [x] `policy.set` accepts a snapshot only with `expires_at`, validates it with the same loader as files, and emits
      `policy.updated`. *(An already expired snapshot, or one for `unattended`, is `-32602` too. `policy.updated` is an
      engine event with `{profile, expires_at}`.)*
- [x] `policy.get`, `policy.grant`, `policy.grants` and `policy.revoke` behave as specified. Grants have an ID, a
      scope and an `expires_at`. *(Specified in [control service](../06-api/control-service.md#policy).)*
- [x] `recording.set` toggles command or output recording for a session, and `session.info` reflects it. *(Output
      recording set here replaces the profile's for the session's next lines.)*
- [ ] Every `user.sock` read and checkpoint method is available on the control service across all sessions.
      *(`records.query`, `records.output` and `events.*` are, across all sessions. **Pending:** `checkpoint.*` is not
      implemented on any endpoint yet (phase 3).)*
- [x] Pushed policy and grants are persisted in the state store (atomic replace, owner-only). *(`state.json`,
      `0600`, rewritten whole with an atomic replace; restored at start. A corrupt or newer file is never
      overwritten, and changes are refused until it is recovered, KNSH-074.)*

**Unit tests**
- `policy_set_requires_expires_at` — FR-POL-50 (`knshd`, `policy_admin`; also `knsh-proto`, `control`).
- `policy_set_emits_policy_updated` — FR-POL-53.
- `grant_revoke_removes_grant` — FR-POL-61.
- `recording_set_updates_session_info` — FR-SES-25 (`knshd`, `supervise`).
- `pause_via_control_matches_user_pause` — FR-SES-10 (`knshd`, `supervisor::hold_tests`: the control method against
  the registry's own pause, which is what a user pause will call).

Also: `creates_agent_sessions_for_the_authority`, `moves_and_ends_agent_sessions_only` and
`refuses_calls_off_the_control_service` (`supervise`); `policy_get_reports_where_a_profile_comes_from`,
`refuses_grants_it_cannot_make` and `persists_pushed_policy_and_grants` (`policy_admin`);
`recording_set_output_overrides_the_profile` (`supervisor`); `persists_snapshots_and_grants_owner_only`,
`keeps_previous_file_when_a_write_fails` and `never_overwrites_an_unreadable_file` (`state`);
`snapshot_takes_the_place_of_the_file`, `expired_snapshot_never_falls_back_to_the_file` and
`refuses_snapshots_that_cannot_be_saved` (`pushed`); `saves_inserts_and_revocations` and `restores_only_live_grants`
(`grants`); `terminates_only_the_sessions_envelopes` (`holds`); `sets_recording_of_agent_sessions_only`
(`knsh-core`, `session`); `reads_grant_params_strictly`, `recording_set_needs_a_setting` and `writes_results`
(`knsh-proto`, `control`).

**Notes**
- Spec gap (settled): the `session.*` method names are now listed in [control service](../06-api/control-service.md#sessions):
  `session.create`, `session.end`, `session.pause`, `session.resume`, `session.take_control`,
  `session.release_control` and `session.list`.
- Spec gap (settled): no params or results were specified for any method of this story. Decided and written in
  [control service](../06-api/control-service.md): `session.create` returns a session token for an agent the
  authority starts itself (an agent session with no envelope); `policy.set` takes `profile`, `policy` (the profile
  text) and `expires_at`; `policy.revoke` answers `{"revoked": bool}`; `recording.set` takes `commands` and/or
  `output`.
- Decided: the authority supervises agents only. Pausing, controlling, ending or changing the recording of a human
  session is `-32003` (FR-SES-22, FR-SES-04).
- Decided: a pushed snapshot takes the place of the file of its name for every load, and once expired loads nothing,
  never the file (FR-POL-52). Pausing sessions at expiry is KNSH-072's.
- Decided: `policy.grant` on `user.sock` stays planned for KNSH-073. The catalogue gained `Availability::AvailableOn`
  so a method can be implemented on some of its endpoints only (likewise `session.list` and `session.end`, served on
  the control service only for now). `policy.check` stays off the control service (KNSH-043).
- Decided: the state store is written by this story and read at start (snapshots and live grants restored). The
  restart scenarios and recovery of a corrupt file are KNSH-074's.
- Known limit: an envelope already running keeps the sandbox profile it started with after a `policy.set`; its lines
  are decided with the new snapshot.
- Known limit: without `recording.set`, `session.info` still reports `output_recording: false` for an agent session
  whose profile records output (the registry does not load profiles; pending since KNSH-053).
- Pending (manual): the methods over XPC with a Developer ID-signed authority, as for KNSH-067 to KNSH-069.
