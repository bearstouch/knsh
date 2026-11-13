# KNSH-112 — systemd units, socket activation and control channel with `SO_PEERCRED`

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Daemon / Authority | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knshd`, `knsh-platform` | platform-support.md (Daemon), process-model.md, platform-support.md (Control channel), FR-AUTH-01 – FR-AUTH-16 |

**Description.** Merged from *systemd user units and socket activation* and *Control channel with `SO_PEERCRED` and executable verification*: they are done and validated together because the control channel is validated over the socket-activated units.

*systemd user units and socket activation.* As a Linux user, I want `knshd` to run as a systemd user unit with socket activation for
`agent.sock` and `user.sock`, so that it starts on first contact, restarts on crash and no other process can claim
its endpoints — as launchd does on macOS.

*Control channel with `SO_PEERCRED` and executable verification.* As the engine on Linux, I need a control channel that only the trusted authority can use, so that
the authority guarantees hold without XPC and code signing.

Scope: a systemd-activated socket for control, peer verification with `SO_PEERCRED` plus executable path and hash
of the peer (via `/proc/<pid>/exe`, checked against the trusted path and hash), trust record stored in the Linux
secret backend, and the same JSON-RPC methods as the XPC service. Envelope profiles must deny this socket.

**Acceptance criteria**
*systemd user units and socket activation*

- [ ] `knshd.socket` units own both sockets; `knshd` receives them via `sd_listen_fds` semantics (implemented
      in-house, no libsystemd crate).
- [ ] `knshd` restarts on crash and exits after 10 idle minutes, like on macOS.
- [ ] Sockets live under the user's runtime or data directory with owner-only permissions.
- [ ] Human sessions with recording off never start `knshd`.

*Control channel with `SO_PEERCRED` and executable verification*

- [ ] A peer whose executable path or hash does not match the trust record is refused.
- [ ] PID-reuse races are handled: verification uses a pidfd or equivalent, not a bare PID.
- [ ] Only one authority at a time; a second registration is refused.
- [ ] Envelope and command profiles deny the control socket (fixed deny).

**Unit tests**
*systemd user units and socket activation*

- `listen_fds_parses_environment`
- `listen_fds_rejects_mismatched_pid`
- `idle_timer_exits_after_ten_minutes` (fake clock)

*Control channel with `SO_PEERCRED` and executable verification*

- `refuses_peer_with_wrong_executable_hash`
- `refuses_peer_with_wrong_uid`
- `verification_uses_pidfd_not_pid`
- `second_authority_registration_refused`

**Integration tests**
*systemd user units and socket activation*

- In a container with a systemd user instance: connect, kill `knshd`, reconnect.

**Notes**
*systemd user units and socket activation*

Linux data paths (XDG directories) are not specified. Add them to `09-reference/file-locations.md` first.

*Control channel with `SO_PEERCRED` and executable verification*

The spec does not say how the authority verifies `knshd` on Linux (FR-AUTH-15 is code-signing-based).
Spec gap: define the reverse check before implementation.
