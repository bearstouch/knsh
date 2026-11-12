# The authority and approvals

The **authority** is the one client trusted to make decisions: approve or deny, push policy, grant, pause and take over sessions, and supply secrets. The engine works fully without one. Integration guidance is in [../integrations/authority-apps.md](../integrations/authority-apps.md); message formats are in [../api/control-service.md](../api/control-service.md).

## Registration

| ID | Requirement |
| --- | --- |
| FR-AUTH-01 | The engine must accept one authority at a time; a second registration is refused until the first disconnects. |
| FR-AUTH-02 | `authority.connected` and `authority.disconnected` must be emitted on connect and disconnect. |

## Trust and verification

| ID | Requirement |
| --- | --- |
| FR-AUTH-10 | The user must trust an authority once with `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>`, confirmed with Touch ID or password inside `knshd`. |
| FR-AUTH-11 | The trust record must be a Keychain item only `knshd` can read. |
| FR-AUTH-12 | The control service must be an XPC Mach service declared in `knshd`'s launchd configuration, so no other process can register it. |
| FR-AUTH-13 | `knshd` must set a peer code-signing requirement: a Developer ID or App Store signature, the trusted team ID and identifier, and no debugging entitlement. |
| FR-AUTH-14 | On each connection `knshd` must also check hardened runtime and the minimum version. |
| FR-AUTH-15 | The authority must verify `knshd` the same way, with a peer requirement for `knshd`'s signature, before sending anything. |
| FR-AUTH-16 | Envelopes must not be able to look up the control service or reach `user.sock`. |

## Decisions

| ID | Requirement |
| --- | --- |
| FR-AUTH-20 | When policy returns ask, the engine must send `decision.requested` to the authority with the request ID, session, actor, command, cwd, matched rule, irreversibility and `timeout_at`. |
| FR-AUTH-21 | The authority answers with `decision.respond`; the verdict is `allow`, `deny` or `rewrite` (with `command`), optionally with a `grant`. |
| FR-AUTH-22 | A request must be tied to its caller. If the caller disconnects, the request must be cancelled with `decision.cancelled`, and a late answer must be ignored. |
| FR-AUTH-23 | The default timeout must be 90 seconds. At the timeout the request is denied (`-32002`). The timeout should be set shorter than the agent CLI's own tool timeout. |
| FR-AUTH-24 | If the authority disconnects, pending requests must be sent again when it reconnects, if they have not timed out. |

## Rewrites

| ID | Requirement |
| --- | --- |
| FR-AUTH-30 | A rewritten line must be evaluated again, once. If it is then asked, the authority sees it with `rewritten_from`. |
| FR-AUTH-31 | A second rewrite must be refused and the line denied. |
| FR-AUTH-32 | A line that contains a redaction marker must not be rewritten, because the marker is not the real value. |
| FR-AUTH-33 | `exec.run` must return the line it actually executed as `executed_command`. |

## Approvals without the authority

| ID | Requirement |
| --- | --- |
| FR-AUTH-40 | `knsh approvals` must list pending requests over `user.sock`. |
| FR-AUTH-41 | `knsh approve <request_id>` must approve one over `user.sock`. `knshd` itself shows the system authentication prompt, with the exact command in it, and approves only after Touch ID or the user's password. |
| FR-AUTH-42 | The command-line tool must not be able to claim that the user is present. |
| FR-AUTH-43 | An agent session must never get a yes/no prompt in its own terminal, because the agent driving that terminal could answer it. |
