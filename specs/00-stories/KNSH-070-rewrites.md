# KNSH-070 — Rewrites

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md), [KNSH-069](KNSH-069-decision-protocol.md) | `knsh-core` | FR-AUTH-30 – FR-AUTH-33, FR-LC-11, FR-REC-04 |

**Description.** As an authority, I want to answer with a rewritten line that is evaluated again safely, so that I
can fix an agent's command instead of only refusing it.

**Acceptance criteria**
- [ ] A rewritten line is re-parsed and re-evaluated once (steps 2 to 5).
- [ ] If the rewritten line asks again, the authority sees it with `rewritten_from`.
- [ ] A second rewrite (from a hook or the authority) is refused and the line denied.
- [ ] A line containing a redaction marker (`«redacted:…»`) cannot be rewritten. Such a rewrite is refused.
- [ ] The record's `command` is the rewritten line, `rewritten_from` is the original, and `exec.run` returns it as
      `executed_command`.

**Unit tests**
- `reevaluates_authority_rewrite_once` — FR-AUTH-30.
- `second_ask_carries_rewritten_from` — FR-AUTH-30.
- `refuses_second_rewrite` — FR-AUTH-31.
- `refuses_rewrite_of_line_with_redaction_marker` — FR-AUTH-32.
- `executed_command_reflects_rewrite` — FR-AUTH-33.
