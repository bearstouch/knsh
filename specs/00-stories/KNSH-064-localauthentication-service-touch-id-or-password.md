# KNSH-064 — LocalAuthentication service (Touch ID or password)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | `knsh-platform` | NFR-SEC-04, FR-AUTH-41, FR-AUTH-42, [macOS services](../08-integrations/macos-services.md) |

**Description.** As `knshd`, I want to show the system authentication prompt myself, with the exact action in it, so
that no client can claim the user is present.

**Acceptance criteria**
- [ ] A `UserPresence` platform trait exposes one operation, "authenticate with reason text", with a fake for tests.
- [ ] The macOS backend calls LocalAuthentication (Touch ID, with a password fallback) from `knshd`, using
      hand-written Objective-C runtime calls or the Swift helper. No third-party crate is used.
- [ ] The prompt text contains the exact command or change being approved.
- [ ] Cancellation, failure, lockout or an unavailable GUI session returns "not authenticated", and the action is
      refused.
- [ ] No API parameter can skip or pre-satisfy the prompt.

**Unit tests**
- `refuses_action_when_authentication_cancelled` — NFR-SEC-04.
- `prompt_reason_contains_exact_command` — FR-AUTH-41.
- `no_parameter_bypasses_prompt` — FR-AUTH-42.

**Integration tests**
- **Pending (manual):** a Touch ID prompt from `knshd` with a logged-in GUI session, and the behaviour without one
  (claim C6 from KNSH-026).

**Notes**
- From KNSH-026 ([C6 results](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7), proposed decision 12): a launchd agent shows the prompt, titled with the process
  name ("knshd is trying to <reason>"), with the reason shown in full. The dialog reached the console even from a job
  without graphics access, so "no GUI" cannot be detected from an error: every outcome other than success, including no
  answer by `timeout_at`, is "not authenticated", and the context is invalidated at the timeout. With the lid closed only
  the password is offered. Still pending: Touch ID with the lid open, an SSH login with nobody at the console, and the
  cancel and timeout outcomes.
