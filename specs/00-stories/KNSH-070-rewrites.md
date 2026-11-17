# KNSH-070 — Rewrites

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md), [KNSH-069](KNSH-069-decision-protocol.md) | `knsh-core` | FR-AUTH-30 – FR-AUTH-33, FR-LC-11, FR-REC-04 |

**Description.** As an authority, I want to answer with a rewritten line that is evaluated again safely, so that I
can fix an agent's command instead of only refusing it.

**Acceptance criteria**
- [x] A rewritten line is re-parsed and re-evaluated once (steps 2 to 5). *(Its own `command.proposed`, hooks and
      policy; step 6 again if it asks.)*
- [x] If the rewritten line asks again, the authority sees it with `rewritten_from`. *(In `decision.requested`;
      local approvals see it too.)*
- [x] A second rewrite (from a hook or the authority) is refused and the line denied. *(In any order; the refused
      line is the first rewrite's, recorded with `rewritten_from`.)*
- [x] A line containing a redaction marker (`«redacted:…»`) cannot be rewritten. Such a rewrite is refused. *(Both
      `«redacted»` and the named `«redacted:<name>»`, in the line or in the rewrite.)*
- [x] The record's `command` is the rewritten line, `rewritten_from` is the original, and `exec.run` returns it as
      `executed_command`. *(`executed_command` is the rewritten line with its absolute paths, FR-LC-13.)*

**Unit tests**
- `reevaluates_authority_rewrite_once` — FR-AUTH-30.
- `second_ask_carries_rewritten_from` — FR-AUTH-30.
- `refuses_second_rewrite` — FR-AUTH-31.
- `refuses_rewrite_of_line_with_redaction_marker` — FR-AUTH-32.
- `executed_command_reflects_rewrite` — FR-AUTH-33.

Also: `finds_plain_and_named_redaction_markers` (`knsh-core`, `redacted`); `sends_rewritten_from_with_second_ask`
(`knshd`, `decisions`). The pipeline itself came with KNSH-050 and KNSH-063 (`reevaluates_rewritten_line_once`,
`denies_on_second_rewrite`, `refuses_rewrites_it_cannot_trust`).

**Notes**
- Found while implementing: the rewrite guard looked only for `«redacted»` (the `Redacted<T>` display text), while
  the redaction engine writes named markers, `«redacted:<name>»` (FR-SEC-10). Both are now markers
  (`holds_redaction_marker`: `«redacted` followed by `»` or `:`), for rewrites (FR-AUTH-32) and for grants made from
  an answer (KNSH-069), so neither turns a marker back into a runnable or stored line once KNSH-090 redacts.
- A received line that already holds marker text cannot be told apart from a redacted one, so it cannot be rewritten
  either; it is still decided like any other line when nobody rewrites it.
