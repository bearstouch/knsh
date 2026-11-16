# KNSH-064 — LocalAuthentication service (Touch ID or password)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | `knsh-platform` | NFR-SEC-04, FR-AUTH-41, FR-AUTH-42, [macOS services](../08-integrations/macos-services.md) |

**Description.** As `knshd`, I want to show the system authentication prompt myself, with the exact action in it, so
that no client can claim the user is present.

**Acceptance criteria**
- [x] A `UserPresence` platform trait exposes one operation, "authenticate with reason text", with a fake for tests.
- [ ] The macOS backend calls LocalAuthentication (Touch ID, with a password fallback) from `knshd`, using
      hand-written Objective-C runtime calls or the Swift helper. No third-party crate is used. *(The backend is
      written with hand-written runtime calls and no third-party crate, but a prompt shown by it has not been observed
      yet and `knshd` does not call it until KNSH-065: pending the manual integration check.)*
- [x] The prompt text contains the exact command or change being approved.
- [x] Cancellation, failure, lockout or an unavailable GUI session returns "not authenticated", and the action is
      refused.
- [x] No API parameter can skip or pre-satisfy the prompt.

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
- Implemented in `knsh-platform` (`presence` module): the `UserPresence` trait, whose one method takes only the
  reason and a timeout; `PromptReason`, which builds the decision 12 text (`approve the agent command: <command> (cwd
  <dir>, session <id>)`, or `<action>: <detail>` for other changes) and escapes backslashes, control characters,
  invisible and bidirectional characters (including tag characters, variation selectors, fillers and
  non-ASCII spaces) and non-UTF-8 path bytes, so nothing in the command can hide or disguise
  part of it; `Authenticated`, a proof only `knsh-platform` can construct (a compile-fail doctest checks this); and
  `NotAuthenticated` (cancelled, failed, lockout, unavailable, timed out, other error code), every variant a refusal.
  The fake is `testing::ScriptedPresence`, which refuses with "timed out" when nothing is scripted.
- The macOS backend `macos::LocalAuthentication` uses hand-written Objective-C runtime calls (`objc_msgSend`) and a
  hand-laid-out reply block with copy and dispose helpers, so the shared answer lives as long as the framework's copy
  of the block. A new `LAContext` per call evaluates `LAPolicyDeviceOwnerAuthentication`;
  `interactionNotAllowed` and the Touch ID reuse duration are never set. At the timeout the context is invalidated and
  the answer is "timed out", even if a late success arrives. A zero timeout refuses without showing a prompt.
- Verified automatically (macOS 26.6.2): the block layout against the real block runtime (`_Block_copy`,
  `_Block_release`), the mapping of real `NSError` values (`LAErrorDomain` and other domains) to refusals, and
  creating an `LAContext`. The ignored test `shows_the_system_prompt` is the manual check for the pending integration
  test. Wiring into `knshd` (approvals, grants, policy edits, trust) comes with KNSH-065, KNSH-066, KNSH-068 and
  KNSH-073. A length limit for very long commands is still to be set (decision 12); the text is never shortened.
