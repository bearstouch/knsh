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

- [x] `knsh authority trust --team-id <id> --identifier <bundle-id> --min-version <v>` asks for Touch ID or
      password inside `knshd`, then stores the trust record. *(`authority.trust` on `user.sock`: `knshd` prompts
      through its `UserPresence` service, naming the authority, and stores only with the resulting proof; observed
      with the scripted prompt in `knshd` tests. **Pending (manual):** the real Touch ID or password dialog from a
      launchd-started `knshd`.)*
- [ ] The trust record is a Keychain item only `knshd` can read. *(Implemented: generic-password item
      `knsh.authority-trust` / `v1` in the file-based login keychain, created by `knshd` with the default access list,
      user interaction disabled, a read failure or a value not in the engine's format refusing everything (decision 11).
      **Pending (manual, claim C5):** the item's access list from a Developer ID-signed `knshd` and across updates, and
      a planted item with an open access list. The throwaway-item round trip is an ignored test.)*
- [x] Replacing an existing trust record also requires authentication. *(The prompt names the old and the new record;
      refused, the old record stays. `replacing_trust_requires_authentication`.)*
- [x] Invalid arguments (a malformed team ID or version) are rejected before the prompt. *(Usage error in the CLI,
      exit 2, nothing sent; `-32602` in `knshd` before the record is read or any prompt shown.)*

*Authority registration*

- [x] `authority.register` succeeds for the first verified connection. *(Through the control endpoint's JSON-RPC
      path in `knshd` tests. **Pending:** over XPC with a Developer ID-signed authority, as for KNSH-067.)*
- [x] A second registration is refused until the first disconnects. *(`-32003`; freed when the authority's control
      connection closes, including when its trust record is replaced.)*
- [x] `authority.connected` and `authority.disconnected` are emitted on register and disconnect. *(As engine events:
      `session_id` and `actor` are `null`, delivered to subscriptions to every session; see
      [event](../05-models/event.md).)*

**Unit tests**
*`knsh authority trust`*

- `stores_trust_after_authentication` — FR-AUTH-10.
- `refuses_without_authentication` — FR-AUTH-10.
- `validates_team_id_and_version_format` — FR-AUTH-10.

*Authority registration*

- `first_registration_succeeds` — FR-AUTH-01.
- `second_registration_refused` — FR-AUTH-01.
- `emits_connected_and_disconnected` — FR-AUTH-02.

Also: `refuses_when_the_record_cannot_be_read`, `keeps_the_previous_record_when_the_write_fails`,
`trust_is_refused_off_user_sock`, `registration_is_refused_off_the_control_service` (`knshd`, `authority`);
`registration_follows_the_authority_connection` (`knshd`, `control`); `stored_record_round_trips` and
`refuses_malformed_stored_records` (`knsh-core`, `authority`); `engine_events_reach_all_scope_subscriptions_in_order`
and `dropped_engine_events_are_reported_as_lost` (`knsh-core`, `event`); `a_new_trust_record_ends_connections_verified_under_the_old_one`
and `set_gate_compiles_and_rejects_nothing_new_without_trust` (`knsh-platform`, `macos::xpc`, real XPC);
`validates_team_id_identifier_and_version_before_sending` and `sends_only_the_authority` (`knsh`, CLI).

**Notes**
*`knsh authority trust`*

- Spec gap: removing or revoking trust is not specified. Propose `knsh authority untrust`, with Touch ID. Not
  implemented here; an unreadable item is removed by hand (`security delete-generic-password -s knsh.authority-trust`).
- Decided while implementing: the record is versioned text (`knsh-authority-trust v1`, then `team_id`, `identifier`,
  `min_version` lines), decoded strictly. A replacement updates the item in place (`SecItemUpdate`, keeping its
  access list) and only after the existing record was read successfully; the signing key's "never overwrite" rule
  stays for the key. Trusting the same record again asks nothing. The running control service switches to the new
  record at once and closes connections verified under the old one.

*Authority registration*

- The spec gives no error code for a refused second registration. Decided: `-32003`.
- Decided while implementing: `authority.connected` and `authority.disconnected` belong to no session, so they are
  **engine events**: the same envelope with `session_id` and `actor` `null`, `seq` in an engine sequence of their own,
  not buffered, delivered only to subscriptions to every session, with `events.lost` (`session_id: null`) on overflow.
  Payload `{}`.
- From KNSH-026 ([C5 and C7 results](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7), proposed decisions 11 and 13): the trust record follows the same Keychain
  rules as the policy key (a read failure on an existing record is tampering). An authority's peer requirement guards
  only what it receives, so its first message (`hello`) must carry nothing sensitive. The authority must bind a
  `CFBundleVersion` into its signature for the `--min-version` check.
