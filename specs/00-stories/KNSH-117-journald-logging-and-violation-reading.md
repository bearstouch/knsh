# KNSH-117 — journald logging and violation reading

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Observability | M (3) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knsh-platform` | platform-support.md (System log), FR-SBX-08 |

**Description.** As an operator on Linux, I want engine logs in journald and sandbox denials reported as
`sandbox.violation`, so that observability matches macOS.

**Acceptance criteria**
- [ ] Engine logs go to journald with the `knsh` identifier, never containing command output or secret values.
- [ ] Landlock/seccomp denials (audit log or `SECCOMP_RET_USER_NOTIF`/errno) are attributed to session and command,
      best effort.

**Unit tests**
- `log_records_never_include_output`
- `violation_parser_extracts_tag`
