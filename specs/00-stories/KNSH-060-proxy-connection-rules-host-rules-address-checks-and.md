# KNSH-060 — Proxy connection rules: host rules, address checks and reporting

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Proxy | XL (8) | [KNSH-018](KNSH-018-event-bus-and-subscriptions.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md), [KNSH-052](KNSH-052-agent-execution-records.md), [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md) | `knsh-proxy`, `knsh-core`, `knsh-platform`, `knshd` | FR-NET-02 – FR-NET-04, FR-NET-11, FR-POL-21, FR-NET-05, FR-NET-07, FR-NET-08, FR-NET-09 |

**Description.** Merged from *Proxy host rules*, *Name resolution and address checks* and *Proxy reporting: `proxy.denied` and record network field*: they are done and validated together because every connection decision is validated by its `proxy.denied` report and record entry.

*Proxy host rules.* As the engine, I want each connection checked against the profile's host rules and the command's
class and approvals, so that upload-capable hosts are reachable only by commands meant to reach them.

*Name resolution and address checks.* As the engine, I want the proxy to resolve names itself and refuse internal addresses, so that DNS
rebinding and direct IP access cannot bypass host rules.

*Proxy reporting: `proxy.denied` and record network field.* As an observer, I want every refused connection reported and every contacted host listed on the
record, so that network behaviour is auditable per command.

**Acceptance criteria**
*Proxy host rules*

- [x] `network.hosts` is open to every command in the session.
- [x] `network.approval_hosts` is reachable only by commands whose class allows it, or that were approved or are
      covered by a grant.
- [x] `network.mode = "none"` refuses every outbound connection except allowed loopback ports.
- [x] Dynamic code is limited to `hosts` and never reaches `approval_hosts`, even if the line was approved.
- [x] The rule check is a pure function of (session profile, line classes, approvals, host).

*Name resolution and address checks*

- [x] IP-literal destinations are refused unless allowlisted.
- [x] The proxy resolves the name itself and refuses it if any chosen address is loopback, link-local or private
      (IPv4 and IPv6), unless allowlisted.
- [x] The proxy connects to the exact address it checked. It never re-resolves between the check and the connect.
- [x] The DNS resolver service is denied inside every profile (checked against KNSH-045 output).
- [x] The resolver sits behind a platform trait, so tests use a fake resolver.

*Proxy reporting: `proxy.denied` and record network field*

- [x] Each refusal emits `proxy.denied` with session, record (when known), host, port and reason.
- [x] The record's `network` field lists hosts contacted and refused for that line.
- [x] Envelope-level connections are attributed to the session, not to any record.

**Unit tests**
*Proxy host rules*

- `hosts_open_to_every_command` — FR-NET-02.
- `approval_host_refused_without_class_or_approval` — FR-NET-03.
- `approval_host_allowed_for_approved_line` — FR-NET-03.
- `mode_none_refuses_all_but_loopback` — FR-NET-04.
- `dynamic_code_never_reaches_approval_hosts` — FR-NET-11, FR-POL-21.

*Name resolution and address checks*

- `refuses_ip_literal_destination` — FR-NET-05.
- `refuses_name_resolving_to_loopback` — FR-NET-07.
- `refuses_name_resolving_to_private_and_link_local` — FR-NET-07.
- `connects_to_checked_address_without_reresolving` — FR-NET-07.
- `allowlisted_private_address_is_permitted` — FR-NET-07.

*Proxy reporting: `proxy.denied` and record network field*

- `emits_proxy_denied_with_reason` — FR-NET-09.
- `record_lists_contacted_and_refused_hosts` — FR-NET-09.
- `envelope_connection_attributed_to_session` — FR-NET-09.

**Notes**
*Name resolution and address checks*

- The spec says "private". Propose covering RFC 1918, fc00::/7, fe80::/10, 169.254/16, 127/8, ::1, 0.0.0.0/8 and
  carrier-grade NAT 100.64/10, and listing these ranges in the spec.

**Implementation status (KNSH-060)**

- `knsh-core`: `check_host` (`policy/network.rs`), the pure host rule check over (network policy, requester, host),
  with `LineAccess::of` taking a line's classes, dynamic flag and approval (an approval, or a grant that answered the
  rules' ask); `host_matches` for profile entries (names, `*.` wildcards, IP addresses). The record's `network` field
  (`NetworkEntry`, merged and capped at 256) and the `proxy.denied` event.
- `knsh-platform`: the `Resolver` trait, `SystemResolver` (`getaddrinfo` through the standard library) and
  `testing::FakeResolver`.
- `knsh-proxy`: `HostRules`, the gate `knshd` runs (`rules.rs`): loopback ports, IP-literal allowlist, host rules,
  one resolution per connection and the internal-address check (`address.rs`); the proxy connects only to the
  checked addresses, in order. Contacts are reported as well as refusals, under the connection lock, so a line's
  reports precede its revocation.
- `knshd`: each envelope's and line's credentials carry a scope; `NetworkReport` logs every refusal, publishes
  `proxy.denied` for live credentials (no record for the envelope) and collects a line's `network` entries, which
  the spawner takes when it revokes the line's credentials and the supervisor writes to the record.
- `knsh-store` and `knsh-proto`: the reserved `network` column is written and read; `records.query` and the event
  notification show it.
- Decisions written into the spec ([network proxy](../03-functional-requirements/network-proxy.md#host-rules-name-resolution-and-address-checks-knsh-060),
  [execution record](../05-models/execution-record.md#network), [event](../05-models/event.md#phase-2-payloads)):
  the internal ranges (the note's proposal plus `192.0.0.0/24`, `198.18.0.0/15`, multicast and reserved, site-local
  and NAT64 / IPv4-mapped forms); one internal address refuses a name; an address listed in a host rule allowlists it
  as a literal and as a resolved address; `localhost` and loopback addresses on `network.loopback` ports are allowed
  in either mode; the envelope never reaches `approval_hosts`; refusals before credentials are known are only logged.
- Pending: `hello` keeps `network_filter: none` until the TLS server-name check (KNSH-061). End-to-end runs of npm,
  pip, cargo and Node through the proxy against real hosts were not run in this change.
