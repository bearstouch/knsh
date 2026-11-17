# Threat-model end-to-end suite (KNSH-075)

One end-to-end case or more per row of the threat model
([security.md](../../specs/04-non-functional-requirements/security.md)), run against real envelopes and real compiled
profiles. The suite is the evidence the phase 2 release gate asks for
([roadmap](../../specs/01-overview/roadmap.md#gates)): every mitigation holds on every macOS version with a runner.

The cases live in `crates/knshd/src/threat_model/` because they drive `knshd`'s own parts: a miniature `knshd`
(`harness.rs`) with the connection server on real `user.sock` and `agent.sock`, signed policy files, the real network
proxy and host rules, the supervisor spawning every line through the real `knsh-exec` and `sandbox-exec`, and the
envelope launcher. Only the name resolver, the authority and the hooks are stand-ins, so nothing leaves the machine
and no person is asked. Every case uses its own temporary home and state directory under `/private/tmp`, never the
user's real one.

## Running it

```sh
scripts/check.sh threat-model    # builds the workspace, runs the cases strictly, writes target/threat-model/report.md
```

`cargo test --workspace` also runs the cases. `cargo test -p knshd` alone does not build `knsh-exec` and `knsh`, so
there every case is reported **pending** ("not built"), loudly; `scripts/check.sh threat-model` sets
`KNSH_THREAT_MODEL_STRICT=1`, which turns that into a failure. The report lists each row, its cases, the result and
anything pending; a case that failed leaves no result and is reported as failed.

## Rows and cases

| Threat | Case | What it shows |
| --- | --- | --- |
| An agent approves its own request | `agent_cannot_approve_own_request` | From a real envelope: `user.sock` refused, `knsh.control` lookup refused by the sandbox; on `agent.sock`, `approval.approve`, `approval.deny`, `policy.grant` not listed and never served |
| An agent slips past command rules | `python_subprocess_git_push_cannot_reach_approval_host` | `python3 -c` running `git push`: the real proxy refuses github.com as `dynamic_code`; the same line reaches `network.hosts`, and a plain `git push` is refused as `approval_required` |
| | `eval_and_absolute_path_bypass_stay_inside_profile` | `/bin/rm`, `env`, `/usr/bin/env`, `command`, `nice`, `nohup`, `env -i`, substitutions: all the denied `rm`; `eval`, `sh -c`, `bash -c`, names from variables and absolute paths run but cannot write outside the profile |
| A binary is swapped between classification and execution | `binary_swapped_after_classification_cannot_exec` | A program planted after the decision is refused at exec by the kernel; a `git` planted first on `PATH` after `git` resolved does not run (the line runs `/usr/bin/git`) |
| An agent escapes through LaunchServices, Apple Events or launchd | `open_osascript_launchctl_denied_by_rule_and_profile` | Denied by rule under `unattended` however spelled; allowed by rule, `open`, an Apple Event and `launchctl submit` still fail under the profile |
| An agent plants code that runs later outside the sandbox | `writes_to_git_hooks_config_rc_files_launchagents_denied` | With the whole home writable, git hooks and config, shell startup files and LaunchAgents refused from a line and from the envelope; `.git` cannot be moved |
| An agent edits policy, hooks or trust | `agent_cannot_edit_policy_hooks_or_trust` | Policies, the configuration file (hooks), the record store and compiled profiles unwritable and unreadable; a tampered policy file is ignored with `policy.invalid` and nothing runs |
| An agent kills `knshd` or squats its endpoints | `envelope_cannot_signal_knshd_and_lines_stop_when_it_dies` | `kill` of `knshd` and of another process refused; `agent.sock` cannot be removed or moved; `knsh -c` runs while `knshd` serves, and not once it is gone |
| An impostor daemon or authority | `impostor_authority_refused` | An ad-hoc-signed authority fails the peer requirement `knshd` compiles (Security framework); the gate refuses it, and everyone while no authority is trusted |
| An agent leaks a secret | `secret_not_visible_to_other_process_groups` | A line cannot read another line's arguments (`KERN_PROCARGS2`), which an unsandboxed reader can |
| An agent sends data out | `exfiltration_blocked_by_host_name_and_address_checks` | IP literal (`ip_literal`), private address (`address_not_allowed`), forged SNI (`server_name_mismatch`) refused with nothing delivered; a direct DNS query and the resolver socket refused |
| Approval fatigue | `repeated_denials_rate_limited_and_grants_reduce_asks` | Five denials in 60 s, then `rate_limit`; a grant lets the asked line run without an ask |

Every refusal is paired, where the machine allows, with a positive control showing the same action succeeds
without the mitigation, so a refusal cannot pass by accident.

## Pending

Recorded in the report, never as passed:

- **Touch ID.** A user approval (FR-AUTH-41 – FR-AUTH-43) and a user grant through `policy.grant` (KNSH-073) need a
  person at the prompt.
- **Developer ID.** An authority accepted by, and an impostor refused by, the launchd-registered control service over
  XPC; the authority checking `knshd`'s signature; the Keychain item that holds authority trust (FR-AUTH-11 –
  FR-AUTH-15). Only the ad-hoc refusal runs here.
- **Phase 3.** Secret injection (FR-SEC-01 – FR-SEC-05); only process-information limits are tested.
- **macOS versions.** CI runs the suite on macOS 14, 15 and 26 (`.github/workflows/ci.yml`, job `threat-model`).
  macOS 27 has no hosted runner yet: **pending**, to be run by hand on a macOS 27 machine before the release.

## Out of scope (not tested)

Per the threat model: malware running outside any session, a compromised authority, a malicious hook the user
installed, and flaws in the macOS sandbox itself.
