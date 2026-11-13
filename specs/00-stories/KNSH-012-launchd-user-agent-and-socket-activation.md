# KNSH-012 — launchd user agent and socket activation

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Daemon | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | `knsh-platform`, `knshd` | [process model](../02-architecture/process-model.md), [endpoints](../02-architecture/endpoints.md) |

**Description.** As the engine, I want launchd to own `knshd`'s sockets and start it on first contact, so that no
other process can claim the endpoints and `knshd` restarts after a crash. Provide the launch agent property list,
install/uninstall commands, and the platform call that receives launchd-created sockets. Phase 1 activates
`user.sock`; `agent.sock` and the XPC service are declared but served in phase 2.

**Acceptance criteria**
- [ ] A launch agent plist declares `user.sock` and `agent.sock` at
      `~/Library/Application Support/knsh/run/`, owner-only, with on-demand start; `knshd` never creates or binds
      them itself.
- [ ] `knshd` obtains its listening sockets from launchd at start; if launchd provides none, it exits with an error
      (it never falls back to binding its own socket).
- [ ] launchd restarts `knshd` after a crash (`KeepAlive` on crash), and a client connecting during restart
      succeeds once `knshd` is back.
- [ ] `knshd` runs without root, as the logged-in user, and refuses to serve a connection whose peer UID differs
      from its own.
- [ ] `knsh` provides install and uninstall of the agent (writes the plist, bootstraps it, removes it).

**Unit tests**
- `refuses_to_start_without_launchd_sockets` — no self-binding.
- `rejects_peer_with_different_uid` — one user per process (fake peer credentials).
- `plist_declares_both_sockets_owner_only` — generated plist content.

**Integration tests**
- Install the agent in a test user session, connect to `user.sock`, observe `knshd` start; kill it; observe restart
  and successful reconnect.
