# KNSH-074 — Fail-closed operation and state across restarts

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Reliability | M (3) | [KNSH-042](KNSH-042-grants.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | `knshd`, `knsh` | NFR-REL-01, NFR-REL-03, NFR-REL-06, NFR-REL-08, NFR-REL-09, [reliability](../04-non-functional-requirements/reliability.md) |

**Description.** As a user, I want agents blocked, not unleashed, whenever any part of the engine is missing, so that
a crash never becomes a bypass.

**Acceptance criteria**
- [x] With `knshd` stopped, `knsh -c` inside an envelope runs nothing, and envelope network fails because the proxy
      is gone. *(Exit 126, "the supervisor is unavailable …; the line did not run" on stderr, never run locally
      (KNSH-049). Under `sandbox-exec` with a compiled envelope profile, the proxy's port is reachable while it
      listens and refused once it is gone, and no other address ever is.)*
- [x] With `knshd` stopped, human sessions keep working and telemetry is dropped. *(Covered by KNSH-021's recording
      tests, `knshd` stopping mid-session and absent from the start; rerun here.)*
- [ ] launchd restarts `knshd` after a crash while envelopes exist. Grants and pushed policy are restored from the
      state store, and authority-supplied state that is memory-only is not. *(Restoring is verified: live grants and
      pushed snapshots come back and decide lines again, expired grants do not, and the state file's closed format
      holds nothing else, so memory-only state (secrets, of which phase 2 injects none; pending asks; sessions) is
      not restored. The launch agent asks for `KeepAlive` → `Crashed` (KNSH-012). **Pending (manual):** observing a
      real launchd restart with live envelopes. **Not covered:** sessions are memory-only, so an envelope started
      before the crash is unknown to the restarted `knshd` and its lines are refused (`-32009`, exit 126) until the
      agent is started again; adopting surviving envelopes needs its own story and spec
      ([reliability](../04-non-functional-requirements/reliability.md#what-survives-a-restart)).)*
- [x] A corrupt or newer state file triggers recovery and is never overwritten. *(At start the file is renamed,
      never over anything, to `state.json.corrupt-<µs>` or `state.json.newer-<µs>`, logged, and the engine starts
      with no grants and no pushed policy (fail closed); saves then work again. A file that cannot be examined or
      set aside is left in place and the store refuses every save, as before
      ([state store](../06-api/control-service.md#state-store)).)*
- [x] The engine works fully without an authority: local profiles apply, and asks are approved locally or denied at
      the timeout. *(Lines run with no hooks and no authority; asks are approved or denied with `knsh approve` and
      `knsh deny` (KNSH-066), and denied with `-32002` at the timeout otherwise.)*

**Unit tests**
- `restores_grants_after_restart` — NFR-REL-06.
- `restores_pushed_policy_after_restart` — NFR-REL-06.
- `corrupt_state_file_is_not_overwritten` — persistence rules.
- `asks_denied_at_timeout_without_authority` — NFR-REL-09.

Also: `sets_aside_a_symlink_without_touching_its_target`, `set_aside_never_replaces_an_earlier_one` and
`freezes_when_the_file_cannot_be_set_aside_or_examined` (`knshd`, `state`); `rename_new_moves_without_replacing`
(`knsh-platform`, `MemFs`) and `rename_new_never_replaces_an_entry` (`knsh-platform`, `RealFs`).

**Integration tests**
- Kill `knshd` during an agent session. A new `knsh -c` fails without running anything, and after the restart the
  next line runs normally. *(`killed_supervisor_runs_nothing_until_restarted` in `knsh`, with the test envelope's
  supervisor standing in for `knshd`; and `envelope_network_fails_once_the_proxy_is_gone` in `knsh-sandbox`. With
  the real `knshd`, the line after a restart runs once the agent is in a session the new `knshd` knows, see the
  third criterion.)*

**Notes**
- The spec said a corrupt or newer state file "triggers recovery" without saying what recovery is. Specified and
  implemented as setting the file aside under a new name, with `Fs::rename_new` (`renamex_np` with `RENAME_EXCL`) so
  that no entry is ever replaced ([state store](../06-api/control-service.md#state-store),
  [file locations](../09-reference/file-locations.md)).
- [Reliability](../04-non-functional-requirements/reliability.md#what-survives-a-restart) now lists what a restart
  keeps and loses, including the session gap above.
