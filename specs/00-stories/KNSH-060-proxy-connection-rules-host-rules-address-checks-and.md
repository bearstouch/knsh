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

- [ ] `network.hosts` is open to every command in the session.
- [ ] `network.approval_hosts` is reachable only by commands whose class allows it, or that were approved or are
      covered by a grant.
- [ ] `network.mode = "none"` refuses every outbound connection except allowed loopback ports.
- [ ] Dynamic code is limited to `hosts` and never reaches `approval_hosts`, even if the line was approved.
- [ ] The rule check is a pure function of (session profile, line classes, approvals, host).

*Name resolution and address checks*

- [ ] IP-literal destinations are refused unless allowlisted.
- [ ] The proxy resolves the name itself and refuses it if any chosen address is loopback, link-local or private
      (IPv4 and IPv6), unless allowlisted.
- [ ] The proxy connects to the exact address it checked. It never re-resolves between the check and the connect.
- [ ] The DNS resolver service is denied inside every profile (checked against KNSH-045 output).
- [ ] The resolver sits behind a platform trait, so tests use a fake resolver.

*Proxy reporting: `proxy.denied` and record network field*

- [ ] Each refusal emits `proxy.denied` with session, record (when known), host, port and reason.
- [ ] The record's `network` field lists hosts contacted and refused for that line.
- [ ] Envelope-level connections are attributed to the session, not to any record.

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
