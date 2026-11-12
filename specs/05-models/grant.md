# Grant

A grant is a time-limited rule added on top of a profile, usually after an approval: "allow `git push` in this session for one hour". Kept in `knshd`'s state store, so it survives restarts.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | ID | Used with `policy.revoke` |
| `scope` | `session` \| `profile` | What the grant applies to |
| `rule` | pattern | The command it allows |
| `expires_at` | timestamp | After this the grant no longer applies |

- Created by the authority (`policy.grant`, or a `grant` in `decision.respond` with `scope` and `duration_s`) or by the user with Touch ID (`policy.grant` on `user.sock`).
- Listed with `policy.grants`; revoked with `policy.revoke`.
- A grant can cover lines that would receive secrets and lines that need `approval_hosts`.
