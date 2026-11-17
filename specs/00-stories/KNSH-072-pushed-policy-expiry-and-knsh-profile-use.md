# KNSH-072 — Pushed-policy expiry and `knsh profile use`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | `knshd`, `knsh` | FR-POL-51, FR-POL-52, FR-SES-13 |

**Description.** As a user, I want sessions on expired pushed policy paused until I act, so that the engine never
silently falls back to another policy.

**Acceptance criteria**
- [x] When a snapshot's `expires_at` passes, every agent session using it is paused (`session.state_changed`).
      *(Checked every second by a watcher thread; "using it" means its profile is the snapshot or `extends` it. A
      session under human control is paused once handed back; human sessions never are. Lines are denied from
      `expires_at` on whatever the check's timing (KNSH-071).)*
- [x] The session resumes when the authority pushes a valid snapshot, or when the user runs `knsh profile use <name>`
      and authenticates with Touch ID. *(A `policy.set` with which the session's profile loads again resumes it under
      its own profile. `knsh profile use` moves every session paused by expiry to `<name>` and resumes it, after
      `knshd`'s own Touch ID or password prompt. **Pending (manual):** the real Touch ID prompt, as for KNSH-065.)*
- [x] `knsh profile use` accepts only signed local profiles. *(A file in the policies directory whose signature
      verifies, loaded from files only. `unattended`, a pushed name, a profile extending a pushed one, a missing,
      unsigned or invalid file are `-32602` before any prompt.)*
- [x] No code path switches a session's policy without one of these two events. *(The only setter,
      `Sessions::select_profile_after_expiry`, takes the prompt's `Authenticated` proof; `session.resume` is refused
      for a session paused by expiry.)*

**Unit tests**
- `pauses_sessions_on_snapshot_expiry` — FR-POL-51 (fake clock; `knshd`, `expiry`).
- `resumes_on_new_snapshot` — FR-POL-51.
- `profile_use_requires_authentication` — FR-POL-51.
- `never_falls_back_silently` — FR-POL-52.

Also: `pauses_sessions_handed_back_after_expiry`, `snapshot_of_another_profile_resumes_nothing`,
`profile_use_accepts_only_signed_local_profiles`, `profile_use_refuses_unsigned_files`, `ended_sessions_are_forgotten`
and `watcher_pauses_without_a_call` (`expiry`); `expired_snapshot_never_falls_back_to_the_file` (`pushed`, now also
listing expired profiles); `selects_profile_of_agent_sessions_only` (`knsh-core`, `session`);
`params_are_parsed_strictly` and `result_round_trips` (`knsh-proto`, `profile_use`);
`validates_the_profile_name_before_sending`, `sends_only_the_profile_and_reports_the_sessions` and
`failure_messages_name_the_refusal` (`knsh`, `cli::profile`).

**Notes**
- Spec gap (settled): which sessions `knsh profile use` applies to was not specified. Decided: every agent session
  paused by expired pushed policy, all at once (the prompt names how many); with none, nothing is asked. Written in
  [`profile.use`](../06-api/user-socket.md#profileuse) and the [CLI](../06-api/cli.md#profile-use).
- Spec gap (settled): params and result of `profile.use`: `{"profile"}` → `{"profile", "sessions"}`.
- Decided: a local profile must not be, or extend, a name the authority pushed a snapshot for: the loader reads a
  snapshot in place of a file of the same name, so the session would not run under the file the user chose.
- Decided: a session the authority paused itself before expiry is not resumed by a new snapshot. A clock that
  cannot be read counts every snapshot as expired, for pausing as for loading.
- Known limit: an envelope already running keeps the sandbox profile it started with; its next lines are decided
  with the selected profile.
- Known limit (pending): `knsh profile use` does not check FR-SES-03 strictness against a parent session that was not
  paused itself; the authenticated user chooses the profile.
- Pending (manual): Touch ID on real hardware.
