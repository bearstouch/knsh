# The authority and approvals

The **authority** is the one client trusted to make decisions: approve or deny, push policy, grant, pause and take over sessions, and supply secrets. The engine works fully without one. Integration guidance is in [../08-integrations/authority-apps.md](../08-integrations/authority-apps.md); message formats are in [../06-api/control-service.md](../06-api/control-service.md).

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

Measured by KNSH-026 ([verification claims C5 and C7](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7)),
with proposed decisions 11 and 13 (pending acceptance): the trust record lives in the file-based keychain under a
Developer ID-signed `knshd`, and a failed read of an existing record is treated as tampering (FR-AUTH-11). launchd
gives the control service name to the first job that declares it, so FR-AUTH-12 holds against agents (which cannot
create launchd jobs) but not against other software of the user; FR-AUTH-15 is what catches an impostor. An XPC peer
requirement guards only what the client receives, so the authority's first message carries nothing sensitive, and
it sends anything else only after a reply has passed its requirement. Peers are identified by the message's audit
token, never by pid.

Implemented in KNSH-068 (FR-AUTH-01, FR-AUTH-02, FR-AUTH-10, FR-AUTH-11): [`authority.trust`](../06-api/user-socket.md#authoritytrust)
stores the record as the Keychain item `knsh.authority-trust` after `knshd`'s own prompt, for a first record and a
replacement alike, and the running control service switches to it at once;
[`authority.register`](../06-api/control-service.md#authorityregister) admits one authority at a time and refuses
others with `-32003`; `authority.connected` and `authority.disconnected` are engine events (no session). Removing
trust is not specified yet (proposed: `knsh authority untrust`, with Touch ID).

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
