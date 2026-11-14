# KNSH-041 — Line verdicts, dynamic-code limits, fixed denies and the `unattended` profile

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Policy | L (5) | [KNSH-036](KNSH-036-wrapper-unwrapping-and-dynamic-code-classification.md), [KNSH-040](KNSH-040-rule-matching-and-precedence.md) | `knsh-core`, `knsh-core` (built-in data) | FR-POL-18, FR-POL-20, FR-POL-21, FR-POL-30, FR-LC-09, FR-AGT-21 |

**Description.** Merged from *Line verdicts, dynamic-code limits and fixed denies* and *`unattended` profile*: they are done and validated together because the `unattended` profile is a verdict configuration validated by the same tests.

*Line verdicts, dynamic-code limits and fixed denies.* As the supervisor, I want one verdict for the whole line plus the capability set its profile may
receive, so that nothing runs before the whole line is decided and dynamic code never inherits more. Scope:
aggregation over all simple commands; dynamic parts evaluated as the profile says, with capabilities clamped to
`network.hosts`, no secrets, no `approval_hosts`; fixed denies that no profile can change.

*`unattended` profile.* As a user who started an agent with `SHELL=knsh` but not through `knsh agent`, I want its commands
supervised and sandboxed under a strict built-in profile that denies anything needing approval, so that misconfigured
setups fail closed. Scope: a shipped, signed-at-build built-in profile; ask verdicts converted to deny with source
`standalone`.

**Acceptance criteria**
*Line verdicts, dynamic-code limits and fixed denies*

- [x] `evaluate_line` returns `LineDecision { verdict, matched_rules, capabilities }`; deny if any part is denied,
  ask if any part asks (FR-POL-18).
- [x] If any part is dynamic, the line's capabilities are clamped: network limited to `hosts`, no secrets, no
  `approval_hosts`, no classes (FR-POL-20/21).
- [x] Engine paths, sockets and the control service are in a fixed deny set compiled into the binary; a profile that
  tries to allow them fails validation (FR-POL-30).
- [x] Any internal error during evaluation yields deny with source `rule` and a reason (fail closed).

*`unattended` profile*

- [ ] A non-interactive `knsh`/`knsh -c` outside any envelope resolves to the `unattended` profile (wiring in part b).
  **Pending:** `knsh-core` provides `load_unattended`; selecting it for such a session is the supervisor's (part b).
- [x] Any `ask` verdict under `unattended` becomes `deny` with a reason that names the profile.
- [x] The profile's contents are documented in the specs.

**Unit tests**
*Line verdicts, dynamic-code limits and fixed denies*

- `one_denied_part_denies_line`.
- `one_ask_part_asks_line`.
- `dynamic_part_clamps_network_to_hosts` — `python3 -c "…git push…"` cannot reach `approval_hosts`.
- `dynamic_part_gets_no_secrets`.
- `profile_allowing_engine_path_is_rejected`.
- `evaluation_error_denies`.

*`unattended` profile*

- `unattended_turns_ask_into_deny`.
- `unattended_allows_plain_read_only_command` — e.g. `ls` (once contents are agreed).

**Notes**
*`unattended` profile*

— The spec does not define the `unattended` profile's contents; propose them in
[../03-functional-requirements/policy.md](../03-functional-requirements/policy.md) before implementing.
Proposed in [policy.md, "The `unattended` profile"](../03-functional-requirements/policy.md#the-unattended-profile)
(KNSH-041).
