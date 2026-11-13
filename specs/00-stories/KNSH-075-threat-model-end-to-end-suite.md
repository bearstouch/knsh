# KNSH-075 — Threat-model end-to-end suite

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Qualification | XL (8) | [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-055](KNSH-055-rate-limiting-of-repeated-denials.md), [KNSH-057](KNSH-057-envelope-profile-and-launch.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-061](KNSH-061-tls-server-name-check.md), [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-066](KNSH-066-local-approvals-approval-knsh-approvals-knsh-approve.md), [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md), [KNSH-073](KNSH-073-policy-grant-on-user-sock-with-touch-id.md) | `tests/` (workspace), `knshd` | NFR-SEC-01 – NFR-SEC-10, [security](../04-non-functional-requirements/security.md), [test strategy](../07-testing/test-strategy.md) |

**Description.** As the release owner, I want one end-to-end test per threat-model row, run against real envelopes
and profiles, so that phase 2 ships with evidence that every mitigation holds.

All tests use temporary directories and an isolated state directory. They are not unit tests: this story's "unit
tests" are the test cases of the suite.

**Acceptance criteria**
- [ ] Every row of the threat model has at least one passing end-to-end test, listed below.
- [ ] Tests that need a Developer ID, Touch ID or macOS 27 are marked **pending** with the reason, never skipped
      silently.
- [ ] The suite runs in CI on macOS 14, 15 and the current release where runners exist. Missing versions are
      recorded as pending.
- [ ] The phase 2 release gate references this suite's report.

**Unit tests**
(end-to-end cases, one or more per threat row)
- `agent_cannot_approve_own_request` — an envelope process cannot connect to `user.sock`, cannot look up
  `knsh.control`, and `approval.approve` is absent on `agent.sock`. (An agent approves its own request.)
- `python_subprocess_git_push_cannot_reach_approval_host` — dynamic code (`python3 -c`) is limited to `hosts`.
  (An agent slips past command rules.)
- `eval_and_absolute_path_bypass_stay_inside_profile` — `eval`, wrappers and `/usr/bin/env` forms are classified and
  confined. (An agent slips past command rules.)
- `binary_swapped_after_classification_cannot_exec` — a binary planted in an untrusted folder fails at exec. (A binary
  is swapped between classification and execution.)
- `open_osascript_launchctl_denied_by_rule_and_profile` — denied by rule, and the system services are also denied in
  the profile. (Escape through LaunchServices, Apple Events or launchd.)
- `writes_to_git_hooks_config_rc_files_launchagents_denied` — fixed write denies hold. (Planting code that runs later.)
- `agent_cannot_edit_policy_hooks_or_trust` — engine paths are unwritable, and a tampered policy file is ignored with
  `policy.invalid`. (An agent edits policy, hooks or trust.)
- `envelope_cannot_signal_knshd_and_lines_stop_when_it_dies` — `kill` of `knshd` from the envelope fails. With
  `knshd` gone, no line runs. (An agent kills `knshd` or squats its endpoints.)
- `impostor_authority_refused` — an ad-hoc-signed authority is refused (pending without a Developer ID). (An impostor
  daemon or authority.)
- `secret_not_visible_to_other_process_groups` — process information is limited to the command's own group.
  Secret injection itself is completed in phase 3. (An agent leaks a secret.)
- `exfiltration_blocked_by_host_name_and_address_checks` — an IP literal, a private address, a forged SNI and a
  direct DNS query are all refused. (An agent sends data out.)
- `repeated_denials_rate_limited_and_grants_reduce_asks` — 5 denials in 60 s trigger `rate_limit`, and a grant
  suppresses the ask. (Approval fatigue.)

**Notes**
- Out-of-scope rows (malware outside sessions, a compromised authority, malicious user hooks, macOS sandbox flaws)
  are documented as not tested.
