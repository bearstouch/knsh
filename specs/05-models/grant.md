# Grant

A grant is a time-limited rule added on top of a profile, usually after an approval: "allow `git push` in this session for one hour". Kept in `knshd`'s [state store](../06-api/control-service.md#state-store), saved before it applies, so it survives restarts (KNSH-071; restoring is checked end to end by KNSH-074).

| Field | Type | Notes |
| --- | --- | --- |
| `id` | ID | Used with `policy.revoke` |
| `scope` | `session` \| `profile` | What the grant applies to: one session (by `session_id`), or every session running under one profile (by name) |
| `rule` | pattern | The command it allows: a command pattern read like an `exec.allow` entry. Confirmed (KNSH-042): the original spec implies this field without naming it |
| `expires_at` | timestamp | From this instant on the grant no longer applies |

- Created by the authority (`policy.grant` on the control service, KNSH-071, or a `grant` in `decision.respond` with `scope` and `duration_s`) or by the user with Touch ID (`policy.grant` on `user.sock`, KNSH-073).
- Listed with `policy.grants`; revoked with `policy.revoke`.
- A grant can cover lines that would receive secrets and lines that need `approval_hosts`.

## Evaluation (KNSH-042)

- A grant only answers an `ask`. A line the rules ask about is allowed when **every** part that asks is a command an
  unexpired, in-scope grant covers; the record's `decision.source` is then `grant`, and `rule_id` names the rule that
  asked. A part the rules deny, or a fixed deny, is never changed by a grant.
- A grant's rule must match the command whatever its unknown arguments become, as an allow rule must: a grant for
  `git push` covers `git push origin main` and `git push $X`, but not `git $X`. A part with no command of its own (a
  line the parser could not read, `[[ … ]]`) is never covered.
- A grant changes only the verdict, never what the line may receive: dynamic code stays limited to `network.hosts`,
  with no approval hosts, secrets or classes (FR-POL-20, FR-POL-21). Under the `unattended` profile, a granted line
  holding dynamic code is still denied.
- Expiry is decided against the time the engine reads from its clock. An expired grant never matches, is not listed
  by `policy.grants` and can no longer be revoked (`policy.revoke` reports it as not found, like an unknown ID). If the
  clock cannot be read, no grant applies.
- A `grant` in `decision.respond` names only `scope` and `duration_s` (KNSH-069). Its rule is the asked line itself:
  the command's name and arguments as written, joined by single spaces (`git push origin main`), scoped to the asking
  session or its profile, and expiring `duration_s` after the answer. Only a line that is one simple command, with no
  wrapper, substitution or other dynamic part, whose every word is known, non-empty and holds no space or `*`, and
  that holds no secret, can be written this way; for any other line no grant is created (`grant_id: null`) and the
  `allow` still applies. Such a grant is **exact**: unlike an allow pattern (FR-POL-16), its rule does not cover the
  same command with more arguments, so a grant for `rm -r build` never covers `rm -r build /`, which the authority
  was never shown.
- The rule is checked when the grant is created; a rule that is not a command pattern (blank, or naming a path) is
  refused. A grant created already expired, or with the ID of a live grant, is refused. `knshd` holds at most 1024
  live grants.
