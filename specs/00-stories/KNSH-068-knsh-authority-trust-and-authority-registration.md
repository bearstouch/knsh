# KNSH-068 — `knsh authority trust` and authority registration

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md), [KNSH-067](KNSH-067-xpc-control-service-with-peer-verification.md) | `knsh`, `knshd`, `knsh-platform` | FR-AUTH-10, FR-AUTH-11, FR-AUTH-01, FR-AUTH-02 |

**Description.** Merged from *`knsh authority trust`* and *Authority registration*: they are done and validated together because registration is the observable result of trust.

*`knsh authority trust`.* As a user, I want to trust one authority app with an explicit command and Touch ID, so that only the
app I chose can decide for my agents.

*Authority registration.* As an authority app, I want to register as the single authority, so that decision requests come to
me.

**Acceptance criteria**
*`knsh authority trust`*

- [ ] `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` asks for Touch ID or
      password inside `knshd`, then stores the trust record.
- [ ] The trust record is a Keychain item only `knshd` can read.
- [ ] Replacing an existing trust record also requires authentication.
- [ ] Invalid arguments (a malformed team ID or version) are rejected before the prompt.

*Authority registration*

- [ ] `authority.register` succeeds for the first verified connection.
- [ ] A second registration is refused until the first disconnects.
- [ ] `authority.connected` and `authority.disconnected` are emitted on register and disconnect.

**Unit tests**
*`knsh authority trust`*

- `stores_trust_after_authentication` — FR-AUTH-10.
- `refuses_without_authentication` — FR-AUTH-10.
- `validates_team_id_and_version_format` — FR-AUTH-10.

*Authority registration*

- `first_registration_succeeds` — FR-AUTH-01.
- `second_registration_refused` — FR-AUTH-01.
- `emits_connected_and_disconnected` — FR-AUTH-02.

**Notes**
*`knsh authority trust`*

- Spec gap: removing or revoking trust is not specified. Propose `knsh authority untrust`, with Touch ID.

*Authority registration*

- The spec gives no error code for a refused second registration. Propose `-32003`.
