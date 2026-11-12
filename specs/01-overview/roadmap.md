# Roadmap

macOS ships first; Linux follows once the macOS engine is stable.

| Phase | Name | Delivers | Safe for agents |
| --- | --- | --- | --- |
| 1 | **Observe** (macOS, advisory) | Integration mode for human zsh and bash, telemetry records, events, `user.sock` and the CLI | No. Labelled advisory: no security guarantees, and not for running agents unattended |
| 2 | **Contain and decide** | Envelopes, the supervisor, `knsh-exec`, deny-by-default profiles, the proxy, `agent.sock`, the XPC control service and authority, signed policy, approvals, rate limiting and standalone rules | Yes. The first release that is safe to give to agents |
| 3 | **Reverse and protect** | Checkpoints with undo and redo, secrets, irreversible-action flags | Yes |
| 4 | **Native interpreter** | Decisions per simple command, including inside scripts and functions | Yes |
| 5 | **Linux** | The Linux backends ([platform support](../architecture/platform-support.md)), behind the same API | Yes |
| 6 | **Later** | Command introspection, an MCP client, session replay, optional structured pipelines | — |

## Gates

- Phase 2 does not start until the platform claims in [../testing/verification-claims.md](../testing/verification-claims.md) are verified.
- The phase 2 parser must meet the exit criterion in [../testing/conformance.md](../testing/conformance.md).
- The Endpoint Security entitlement application (decision 3 in [../reference/decisions.md](../reference/decisions.md)) should be submitted now, independent of phase.
- Name checks (decision 2) must be completed before any public announcement.
